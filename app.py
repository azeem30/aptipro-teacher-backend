from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from db import get_db_connection
from dotenv import load_dotenv
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://aptipro-teacher-frontend.vercel.app",
            "http://localhost:3000"  # For local development
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

load_dotenv()
key = os.getenv("KEY")

@app.before_request
def before_request():
    global connection
    connection = get_db_connection()

@app.teardown_request
def teardown_request(exception):
    global connection
    if connection:
        connection.close()

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'https://aptipro-teacher-frontend.vercel.app')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

def encrypt_data(data):
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data 

def decrypt_data(encrypted_data):
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    return decrypted_data

@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()
        required_fields = ['id', 'name', 'email', 'password', 'department']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"success": False, "message": f"{field} is required"}), 400
        encrypted_password = encrypt_data(data['password'])
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM teachers WHERE email = %s", (data['email'],))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "Email already exists"}), 400
            cursor.execute("SELECT id FROM teachers WHERE id = %s", (data['id'],))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "ID already exists"}), 400
            cursor.execute("SELECT department_name FROM department WHERE department_name = %s", 
                          (data['department'],))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Invalid department"}), 400
            cursor.execute(
                """INSERT INTO teachers 
                (id, email, name, dept_name, password) 
                VALUES (%s, %s, %s, %s, %s)""",
                (data['id'], data['email'], data['name'], 
                 data['department'], encrypted_password)
            )
            connection.commit()
            return jsonify({
                "success": True,
                "message": "Teacher account created successfully"
            }), 201 
    except Exception as e:
        connection.rollback()
        return jsonify({
            "success": False,
            "message": "An error occurred during signup",
            "error": str(e)
        }), 500

@app.route("/verify", methods=["POST"])
def verify():
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"success": False, "message": "Email is required"}), 400
        email = data['email']
        with connection.cursor() as cursor:
            cursor.execute("SELECT email FROM teachers WHERE email = %s", (email,))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Email not found"
                }), 404
            cursor.execute(
                "UPDATE teachers SET verified = 1 WHERE email = %s",
                (email,)
            )
            connection.commit()
            return jsonify({
                "success": True,
                "message": "Account verified successfully"
            }), 200   
    except Exception as e:
        connection.rollback()
        return jsonify({
            "success": False,
            "message": "An error occurred during verification",
            "error": str(e)
        }), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"success": False, "message": "Email and password are required"}), 400
        email = data['email']
        password = data['password']
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, email, name, dept_name, password, verified 
                FROM teachers WHERE email = %s""",
                (email,)
            )
            teacher = cursor.fetchone()
            if not teacher:
                return jsonify({
                    "success": False,
                    "message": "Invalid email or password"
                }), 401
            stored_password = teacher["password"]  
            decrypted_password = decrypt_data(stored_password)
            if password != decrypted_password:
                return jsonify({
                    "success": False,
                    "message": "Invalid email or password"
                }), 401
            if not teacher["verified"]: 
                return jsonify({
                    "success": False,
                    "message": "Account not verified. Please check your email."
                }), 403
            cursor.execute(
                "SELECT subject_name FROM subjects WHERE dept_name = %s",
                (teacher["dept_name"],)
            )
            subjects = cursor.fetchall()
            subjects_list = [subject["subject_name"] for subject in subjects]
            cursor.execute(
                """SELECT COUNT(*) FROM tests WHERE teacher = %s""",
                (email, )
            )
            tests_created = cursor.fetchone()["COUNT(*)"]
            cursor.execute(
                """SELECT COUNT(*) FROM results WHERE teacher_email = %s""",
                (email, )
            )
            results_analyzed = cursor.fetchone()["COUNT(*)"]
            user_data = {
                "id": teacher["id"],
                "email": teacher["email"],
                "name": teacher["name"],
                "department": teacher["dept_name"],
                "verified": teacher["verified"],
                "subjects": subjects_list,
                "tests_created": tests_created,
                "results_analyzed": results_analyzed
            }
            return jsonify({
                "success": True,
                "message": "Login successful",
                "user": user_data
            })
    except Exception as e:
        print(str(e))
        return jsonify({
            "success": False,
            "message": "An error occurred during login",
            "error": str(e)
        }), 500

@app.route("/create_test", methods=["POST"])
def create_test():
    try:
        data = request.get_json()
        required_fields = [
            'id', 'name', 'marks', 'totalQuestions', 'duration',
            'difficulty', 'subject', 'createdBy', 'scheduleDate', 'dept_name'
        ]
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    "success": False,
                    "message": f"{field} is required"
                }), 400
        valid_difficulties = ['easy', 'medium', 'hard']
        if data['difficulty'].lower() not in valid_difficulties:
            return jsonify({
                "success": False,
                "message": f"Difficulty must be one of: {', '.join(valid_difficulties)}"
            }), 400
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM teachers WHERE email = %s", (data['createdBy'],))
            if not cursor.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Teacher not found"
                }), 404
            cursor.execute(
                """INSERT INTO tests 
                (id, name, marks, questions_count, duration, difficulty, 
                 subject, teacher, scheduled_at, dept_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (int(data['id']), data['name'], data['marks'], data['totalQuestions'],
                 data['duration'], data['difficulty'], data['subject'],
                 data['createdBy'], data.get('scheduleDate'), data['dept_name'])
            )
            connection.commit()
            return jsonify({
                "success": True,
                "message": "Test created successfully",
            }), 201
    except Exception as e:
        connection.rollback()
        print(str(e))
        return jsonify({
            "success": False,
            "message": "An error occurred while creating the test",
            "error": str(e)
        }), 500

@app.route("/results", methods=["GET"])
def get_results():
    try:
        data = request.args
        if 'email' not in data:
            return jsonify({"success": False, "message": "Teacher email is required"}), 400
        teacher_email = data['email']
        with connection.cursor() as cursor:
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
        return jsonify({
            "success": False,
            "message": "An error occurred while fetching results",
            "error": str(e)
        }), 500

@app.route("/questions", methods=["POST"])
def create_question():
    try:
        data = request.get_json()
        required_fields = ["id", "question", "optionA", "optionB", "optionC", "optionD", "correctOption", "difficulty", "subject"]
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"success": False, "message": f"{field} is required"}), 400
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO mcq VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (int(data["id"]), data["question"], data["optionA"], data["optionB"], data["optionC"], data["optionD"],
                data["correctOption"], data["difficulty"], data["subject"])
            )
            connection.commit()
            return jsonify({"success": True, "message": "Question created successfully"}), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "An error occurred while creating question",
            "error": str(e)
        }), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)