from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response

app = Flask(__name__)
app.secret_key = "dev-secret-change-this"  # needed for session + flash

# ----------------------------------------
# "Database" in memory (for now)
# ----------------------------------------
# This will reset when you stop the server, but is OK for now.
# Structure:
# users = {
#   "mobile_number": {
#       "password": "...",
#       "aadhaar": "...",
#       "transfer_pin": "123456",
#       "signatures": [sig1, sig2, sig3],
#       "history": [ {id, file_type, status, details_text} ]
#   }
# }
users = {}

# OTP used everywhere for demo
DEMO_OTP = "123456"


def get_current_user():
    mobile = session.get("mobile")
    if not mobile:
        return None
    return users.get(mobile)


# ----------------------------------------
# HOME / LOGIN
# ----------------------------------------
@app.route("/")
def index():
    if "mobile" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "").strip()

        user = users.get(mobile)
        if not user or user["password"] != password:
            flash("Wrong mobile number or password.", "error")
            return redirect(url_for("login"))

        session["mobile"] = mobile
        flash("Signed in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# ----------------------------------------
# SIGN-UP FLOW
# phone -> phone OTP -> password -> Aadhaar -> Aadhaar OTP
# -> transfer PIN -> 3 signatures -> done
# ----------------------------------------

@app.route("/signup/phone", methods=["GET", "POST"])
def signup_phone():
    # reset any old signup progress
    if request.method == "GET":
        session.pop("signup", None)

    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()

        if not mobile:
            flash("Please enter mobile number.", "error")
            return redirect(url_for("signup_phone"))

        if mobile in users:
            flash("This mobile number is already registered. Please login.", "error")
            return redirect(url_for("login"))

        session["signup"] = {
            "mobile": mobile,
            "phone_otp": DEMO_OTP,
            "phone_verified": False,
            "aadhaar_verified": False,
            "signatures": []
        }
        flash(f"OTP sent to {mobile} (Demo OTP: {DEMO_OTP}).", "info")
        return redirect(url_for("signup_phone_otp"))

    return render_template("signup_phone.html")


@app.route("/signup/phone/otp", methods=["GET", "POST"])
def signup_phone_otp():
    signup = session.get("signup")
    if not signup:
        flash("Signup session expired. Start again.", "error")
        return redirect(url_for("signup_phone"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if otp == signup["phone_otp"]:
            signup["phone_verified"] = True
            session["signup"] = signup
            flash("Mobile number verified.", "success")
            return redirect(url_for("signup_password"))
        else:
            flash("Wrong OTP. Try again. (Demo OTP is 123456)", "error")
            return redirect(url_for("signup_phone_otp"))

    return render_template("signup_phone_otp.html", mobile=signup["mobile"], demo_otp=signup["phone_otp"])


@app.route("/signup/password", methods=["GET", "POST"])
def signup_password():
    signup = session.get("signup")
    if not signup or not signup.get("phone_verified"):
        flash("Verify mobile first.", "error")
        return redirect(url_for("signup_phone"))

    if request.method == "POST":
        password = request.form.get("password", "").strip()
        if len(password) < 4:
            flash("Password must be at least 4 characters.", "error")
            return redirect(url_for("signup_password"))

        signup["password"] = password
        session["signup"] = signup
        return redirect(url_for("signup_aadhaar"))

    return render_template("signup_password.html")


@app.route("/signup/aadhaar", methods=["GET", "POST"])
def signup_aadhaar():
    signup = session.get("signup")
    if not signup or "password" not in signup:
        flash("Complete previous step first.", "error")
        return redirect(url_for("signup_phone"))

    if request.method == "POST":
        aadhaar = request.form.get("aadhaar", "").strip()
        if len(aadhaar) != 12 or not aadhaar.isdigit():
            flash("Enter a 12-digit Aadhaar number.", "error")
            return redirect(url_for("signup_aadhaar"))

        signup["aadhaar"] = aadhaar
        signup["aadhaar_otp"] = DEMO_OTP
        session["signup"] = signup
        flash("OTP is sent to the Aadhaar registered mobile number. (Demo OTP: 123456)", "info")
        return redirect(url_for("signup_aadhaar_otp"))

    return render_template("signup_aadhaar.html")


@app.route("/signup/aadhaar/otp", methods=["GET", "POST"])
def signup_aadhaar_otp():
    signup = session.get("signup")
    if not signup or "aadhaar" not in signup:
        flash("Complete Aadhaar step first.", "error")
        return redirect(url_for("signup_aadhaar"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if otp == signup["aadhaar_otp"]:
            signup["aadhaar_verified"] = True
            session["signup"] = signup
            flash("Aadhaar verified.", "success")
            return redirect(url_for("signup_pin"))
        else:
            flash("Wrong OTP for Aadhaar. (Demo OTP is 123456)", "error")
            return redirect(url_for("signup_aadhaar_otp"))

    return render_template(
        "signup_aadhaar_otp.html",
        aadhaar=signup["aadhaar"],
        demo_otp=signup["aadhaar_otp"]
    )


@app.route("/signup/pin", methods=["GET", "POST"])
def signup_pin():
    signup = session.get("signup")
    if not signup or not signup.get("aadhaar_verified"):
        flash("Complete Aadhaar verification first.", "error")
        return redirect(url_for("signup_aadhaar"))

    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        if len(pin) != 6 or not pin.isdigit():
            flash("Transfer PIN must be 6 digits.", "error")
            return redirect(url_for("signup_pin"))

        signup["transfer_pin"] = pin
        session["signup"] = signup
        return redirect(url_for("signup_signature", step=1))

    return render_template("signup_pin.html")


@app.route("/signup/signature/<int:step>", methods=["GET", "POST"])
def signup_signature(step):
    if step not in (1, 2, 3):
        flash("Invalid signature step.", "error")
        return redirect(url_for("signup_pin"))

    signup = session.get("signup")
    if not signup or "transfer_pin" not in signup:
        flash("Set transfer PIN first.", "error")
        return redirect(url_for("signup_pin"))

    if request.method == "POST":
        sig_data = request.form.get("signature_data", "").strip()
        if not sig_data:
            flash("Please draw your signature before continuing.", "error")
            return redirect(url_for("signup_signature", step=step))

        signup["signatures"].append(sig_data)
        session["signup"] = signup

        if step < 3:
            return redirect(url_for("signup_signature", step=step + 1))
        else:
            # Finalize user creation
            mobile = signup["mobile"]
            users[mobile] = {
                "password": signup["password"],
                "aadhaar": signup["aadhaar"],
                "transfer_pin": signup["transfer_pin"],
                "signatures": signup["signatures"],
                "history": []
            }
            session.pop("signup", None)
            flash("Account created successfully. Please login.", "success")
            return redirect(url_for("signup_done"))

    return render_template("signup_signature.html", step=step)


@app.route("/signup/done")
def signup_done():
    return render_template("signup_done.html")


# ----------------------------------------
# DASHBOARD (SCREEN 2 + HISTORY EMPTY)
# ----------------------------------------
@app.route("/dashboard")
def dashboard():
    user = get_current_user()
    if not user:
        flash("Please login.", "error")
        return redirect(url_for("login"))

    history = user["history"]
    return render_template("dashboard.html", history=history)


# ----------------------------------------
# FILE FORMS (VEHICLE / PROPERTY)
# ----------------------------------------
@app.route("/file/vehicle", methods=["GET", "POST"])
def file_vehicle():
    user = get_current_user()
    if not user:
        flash("Please login.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        owner_name = request.form.get("owner_name", "").strip()
        reg_number = request.form.get("reg_number", "").strip()
        to_name = request.form.get("to_name", "").strip()

        details = f"Vehicle Transfer: Owner={owner_name}, RegNo={reg_number}, To={to_name}"
        session["current_doc"] = {
            "file_type": "vehicle",
            "details": details
        }
        return redirect(url_for("enter_pin"))

    return render_template("vehicle_form.html")


@app.route("/file/property", methods=["GET", "POST"])
def file_property():
    user = get_current_user()
    if not user:
        flash("Please login.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        owner_name = request.form.get("owner_name", "").strip()
        property_id = request.form.get("property_id", "").strip()
        to_name = request.form.get("to_name", "").strip()

        details = f"Property Transfer: Owner={owner_name}, PropertyID={property_id}, To={to_name}"
        session["current_doc"] = {
            "file_type": "property",
            "details": details
        }
        return redirect(url_for("enter_pin"))

    return render_template("property_form.html")


# ----------------------------------------
# ENTER TRANSFER PIN (SCREEN 5 / 7 / 11)
# ----------------------------------------
@app.route("/enter-pin", methods=["GET", "POST"])
def enter_pin():
    user = get_current_user()
    if not user:
        flash("Please login.", "error")
        return redirect(url_for("login"))

    if "current_doc" not in session:
        flash("Please select a file first.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        if pin == user["transfer_pin"]:
            return redirect(url_for("sign_document"))
        else:
            # Wrong transfer pin -> similar to SCREEN 7 / 11
            flash("Wrong transfer PIN. Try again or use Forgot PIN flow (not yet added).", "error")
            return redirect(url_for("enter_pin"))

    return render_template("enter_pin.html")


# ----------------------------------------
# SIGN DOCUMENT (SCREEN 8) + RESULT (SCREEN 9 / 10)
# ----------------------------------------
@app.route("/sign-document", methods=["GET", "POST"])
def sign_document():
    user = get_current_user()
    if not user:
        flash("Please login.", "error")
        return redirect(url_for("login"))

    current_doc = session.get("current_doc")
    if not current_doc:
        flash("No document in progress.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        sig_data = request.form.get("signature_data", "").strip()
        if not sig_data:
            flash("Please draw your signature before continuing.", "error")
            return redirect(url_for("sign_document"))

        # Simple demo "matching" - we just check user has stored signatures
        # In real life you would compare signatures.
        success = len(user["signatures"]) >= 1

        doc_id = len(user["history"]) + 1
        status = "success" if success else "failed"
        history_entry = {
            "id": doc_id,
            "file_type": current_doc["file_type"],
            "status": status,
            "details": current_doc["details"]
        }
        user["history"].append(history_entry)
        session["last_doc_id"] = doc_id
        session.pop("current_doc", None)

        if success:
            return redirect(url_for("result_success"))
        else:
            return redirect(url_for("result_failure"))

    return render_template("sign_document.html")


@app.route("/result/success")
def result_success():
    user = get_current_user()
    if not user:
        flash("Please login.", "error")
        return redirect(url_for("login"))

    doc_id = session.get("last_doc_id")
    if not doc_id:
        return redirect(url_for("dashboard"))

    return render_template("result_success.html", doc_id=doc_id)


@app.route("/result/failure")
def result_failure():
    user = get_current_user()
    if not user:
        flash("Please login.", "error")
        return redirect(url_for("login"))

    return render_template("result_failure.html")


@app.route("/download/<int:doc_id>")
def download_document(doc_id):
    user = get_current_user()
    if not user:
        flash("Please login.", "error")
        return redirect(url_for("login"))

    # Find document in history
    doc = None
    for h in user["history"]:
        if h["id"] == doc_id:
            doc = h
            break

    if not doc:
        flash("Document not found.", "error")
        return redirect(url_for("dashboard"))

    content = f"E-Doc Transfer Copy\n\nType: {doc['file_type']}\nStatus: {doc['status']}\nDetails: {doc['details']}\n"
    response = make_response(content)
    response.headers["Content-Type"] = "text/plain"
    response.headers["Content-Disposition"] = f"attachment; filename=transfer_{doc_id}.txt"
    return response


# ----------------------------------------
# RUN
# ----------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
