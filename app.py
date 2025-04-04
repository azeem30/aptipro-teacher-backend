import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from db import get_db_connection
from typing import Dict, List, Optional

# Load environment variables
load_dotenv()

# Constants
VALID_DIFFICULTIES = ['easy', 'medium', 'hard']
DEFAULT_PORT = 5000
KEY = os.getenv("KEY")

class FlaskApp:
    def __init__(self):
        self.app = Flask(__name__)
        self.connection = None
        self.cipher_suite = Fernet(KEY)
        self._configure_app()
        self._register_routes()
        self._register_middlewares()

    def _configure_app(self) -> None:
        """Configure Flask application settings and CORS."""
        CORS(self.app, resources={
            r"/*": {
                "origins": [
                    "https://aptipro-teacher-frontend.vercel.app",
                    "http://localhost:3000"  
                ],
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"]
            }
        })

    def _register_middlewares(self) -> None:
        """Register application middleware functions."""
        self.app.before_request(self._before_request)
        self.app.teardown_request(self._teardown_request)
        self.app.after_request(self._after_request)

    def _register_routes(self) -> None:
        """Register application routes."""
        routes = [
            ("/signup", self.signup, ["POST"]),
            ("/verify", self.verify, ["POST"]),
            ("/login", self.login, ["POST"]),
            ("/create_test", self.create_test, ["POST"]),
            ("/results", self.get_results, ["GET"]),
            ("/questions", self.create_question, ["POST"])
        ]
        
        for route, handler, methods in routes:
            self.app.route(route, methods=methods)(handler)

    def _before_request(self) -> None:
        """Establish database connection before each request."""
        self.connection = get_db_connection()

    def _teardown_request(self, exception: Optional[Exception]) -> None:
        """Close database connection after each request."""
        if self.connection:
            self.connection.close()

    def _after_request(self, response) -> None:
        """Add CORS headers to each response."""
        response.headers.add('Access-Control-Allow-Origin', 'https://aptipro-teacher-frontend.vercel.app')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    def encrypt_data(self, data: str) -> bytes:
        """Encrypt sensitive data using Fernet encryption."""
        return self.cipher_suite.encrypt(data.encode())

    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt data using Fernet encryption."""
        return self.cipher_suite.decrypt(encrypted_data).decode()

    def validate_required_fields(self, data: Dict, required_fields: List[str]) -> Optional[Dict]:
        """Validate that all required fields are present in the request data."""
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            return {
                "success": False,
                "message": f"Missing required fields: {', '.join(missing_fields)}"
            }
        return None

    def signup(self) -> Dict:
        """Handle teacher signup requests."""
        try:
            data = request.get_json()
            required_fields = ['id', 'name', 'email', 'password', 'department']
            
            if validation_error := self.validate_required_fields(data, required_fields):
                return jsonify(validation_error), 400

            with self.connection.cursor() as cursor:
                cursor.execute("SELECT id FROM teachers WHERE email = %s OR id = %s", 
                             (data['email'], data['id']))
                if cursor.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "Email or ID already exists"
                    }), 400
                cursor.execute("SELECT department_name FROM department WHERE department_name = %s", 
                              (data['department'],))
                if not cursor.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "Invalid department"
                    }), 400

                # Create new teacher account
                encrypted_password = self.encrypt_data(data['password'])
                cursor.execute(
                    """INSERT INTO teachers 
                    (id, email, name, dept_name, password) 
                    VALUES (%s, %s, %s, %s, %s)""",
                    (data['id'], data['email'], data['name'], 
                     data['department'], encrypted_password)
                )
                self.connection.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Teacher account created successfully"
                }), 201

        except Exception as e:
            self.connection.rollback()
            return jsonify({
                "success": False,
                "message": "An error occurred during signup",
                "error": str(e)
            }), 500

    def verify(self) -> Dict:
        """Handle account verification requests."""
        try:
            data = request.get_json()
            
            if not data or 'email' not in data:
                return jsonify({
                    "success": False,
                    "message": "Email is required"
                }), 400

            with self.connection.cursor() as cursor:
                cursor.execute("SELECT email FROM teachers WHERE email = %s", (data['email'],))
                if not cursor.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "Email not found"
                    }), 404

                cursor.execute(
                    "UPDATE teachers SET verified = 1 WHERE email = %s",
                    (data['email'],)
                )
                self.connection.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Account verified successfully"
                }), 200

        except Exception as e:
            self.connection.rollback()
            return jsonify({
                "success": False,
                "message": "An error occurred during verification",
                "error": str(e)
            }), 500

    def login(self) -> Dict:
        """Handle teacher login requests."""
        try:
            data = request.get_json()
            
            if validation_error := self.validate_required_fields(data, ['email', 'password']):
                return jsonify(validation_error), 400

            with self.connection.cursor() as cursor:
                cursor.execute(
                    """SELECT id, email, name, dept_name, password, verified 
                    FROM teachers WHERE email = %s""",
                    (data['email'],)
                )
                teacher = cursor.fetchone()
                
                if not teacher:
                    return jsonify({
                        "success": False,
                        "message": "Invalid email or password"
                    }), 401

                # Verify password
                decrypted_password = self.decrypt_data(teacher["password"])
                if data['password'] != decrypted_password:
                    return jsonify({
                        "success": False,
                        "message": "Invalid email or password"
                    }), 401

                # Check if account is verified
                if not teacher["verified"]: 
                    return jsonify({
                        "success": False,
                        "message": "Account not verified. Please check your email."
                    }), 403

                # Get teacher's subjects
                cursor.execute(
                    "SELECT subject_name FROM subjects WHERE dept_name = %s",
                    (teacher["dept_name"],)
                )
                subjects = [subject["subject_name"] for subject in cursor.fetchall()]

                # Get teacher statistics
                cursor.execute(
                    """SELECT COUNT(*) FROM tests WHERE teacher = %s""",
                    (data['email'],)
                )
                tests_created = cursor.fetchone()["COUNT(*)"]

                cursor.execute(
                    """SELECT COUNT(*) FROM results WHERE teacher_email = %s""",
                    (data['email'],)
                )
                results_analyzed = cursor.fetchone()["COUNT(*)"]

                # Prepare response data
                user_data = {
                    "id": teacher["id"],
                    "email": teacher["email"],
                    "name": teacher["name"],
                    "department": teacher["dept_name"],
                    "verified": teacher["verified"],
                    "subjects": subjects,
                    "tests_created": tests_created,
                    "results_analyzed": results_analyzed
                }

                return jsonify({
                    "success": True,
                    "message": "Login successful",
                    "user": user_data
                })

        except Exception as e:
            self.app.logger.error(f"Login error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred during login",
                "error": str(e)
            }), 500

    def create_test(self) -> Dict:
        """Handle test creation requests."""
        try:
            data = request.get_json()
            required_fields = [
                'id', 'name', 'marks', 'totalQuestions', 'duration',
                'difficulty', 'subject', 'createdBy', 'scheduleDate', 'dept_name'
            ]
            
            if validation_error := self.validate_required_fields(data, required_fields):
                return jsonify(validation_error), 400

            if data['difficulty'].lower() not in VALID_DIFFICULTIES:
                return jsonify({
                    "success": False,
                    "message": f"Difficulty must be one of: {', '.join(VALID_DIFFICULTIES)}"
                }), 400

            with self.connection.cursor() as cursor:
                # Verify teacher exists
                cursor.execute("SELECT id FROM teachers WHERE email = %s", (data['createdBy'],))
                if not cursor.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "Teacher not found"
                    }), 404

                # Create new test
                cursor.execute(
                    """INSERT INTO tests 
                    (id, name, marks, questions_count, duration, difficulty, 
                     subject, teacher, scheduled_at, dept_name)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (int(data['id']), data['name'], data['marks'], data['totalQuestions'],
                     data['duration'], data['difficulty'], data['subject'],
                     data['createdBy'], data.get('scheduleDate'), data['dept_name'])
                )
                self.connection.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Test created successfully",
                }), 201

        except Exception as e:
            self.connection.rollback()
            self.app.logger.error(f"Test creation error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred while creating the test",
                "error": str(e)
            }), 500

    def get_results(self) -> Dict:
        """Handle requests for teacher's results."""
        try:
            teacher_email = request.args.get('email')
            
            if not teacher_email:
                return jsonify({
                    "success": False,
                    "message": "Teacher email is required"
                }), 400

            with self.connection.cursor() as cursor:
                cursor.execute(
                    """SELECT results.*, students.*
                    FROM results
                    JOIN students ON results.student_email = students.email
                    WHERE results.teacher_email = %s""",
                    (teacher_email,)
                )
                results = cursor.fetchall()
                
                return jsonify({
                    "success": True,
                    "results": results
                }), 200

        except Exception as e:
            self.app.logger.error(f"Results fetch error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred while fetching results",
                "error": str(e)
            }), 500

    def create_question(self) -> Dict:
        """Handle question creation requests."""
        try:
            data = request.get_json()
            required_fields = [
                "id", "question", "optionA", "optionB", "optionC", "optionD", 
                "correctOption", "difficulty", "subject"
            ]
            
            if validation_error := self.validate_required_fields(data, required_fields):
                return jsonify(validation_error), 400

            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO mcq VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (int(data["id"]), data["question"], data["optionA"], data["optionB"], 
                     data["optionC"], data["optionD"], data["correctOption"], 
                     data["difficulty"], data["subject"])
                )
                self.connection.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Question created successfully"
                }), 200

        except Exception as e:
            self.connection.rollback()
            self.app.logger.error(f"Question creation error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "An error occurred while creating question",
                "error": str(e)
            }), 500

    def run(self):
        """Run the Flask application."""
        port = int(os.environ.get('PORT', DEFAULT_PORT))
        self.app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
                   host='0.0.0.0', port=port)

if __name__ == "__main__":
    app = FlaskApp()
    app.run()