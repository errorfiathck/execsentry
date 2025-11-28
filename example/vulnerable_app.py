import os
import subprocess
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_DIR = "uploads"
PLUGIN_DIR = "plugins"   # Unsafe plugin directory
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(PLUGIN_DIR, exist_ok=True)


#########################################
# 1. VULNERABLE FILE UPLOAD + EXECUTION
#########################################
@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file"}), 400

    # ❌ Vulnerable: naive securing + storing arbitrary files
    filename = secure_filename(file.filename)
    path = os.path.join(UPLOAD_DIR, filename)
    file.save(path)

    # ❌ Vulnerable: Automatically execute uploaded files
    try:
        output = subprocess.check_output(path, shell=False)
        return jsonify({
            "status": "executed",
            "output": output.decode(errors="ignore")
        })
    except Exception as e:
        return jsonify({
            "status": "saved",
            "message": str(e)
        })


#########################################
# 2. REMOTE EXECUTION BY FILENAME
#########################################
@app.route("/run", methods=["GET"])
def run_file():
    """
    Example URL:
    /run?file=myprog.exe
    """
    user_file = request.args.get("file")
    if not user_file:
        return jsonify({"error": "No file provided"}), 400

    path = os.path.join(UPLOAD_DIR, user_file)

    # ❌ Vulnerable: no validation, directly executed
    try:
        output = subprocess.check_output(path, shell=False)
        return jsonify({
            "executed": True,
            "output": output.decode(errors="ignore")
        })
    except Exception as e:
        return jsonify({"executed": False, "error": str(e)})


#########################################
# 3. UNSAFE SYSTEM() CALL
#########################################
@app.route("/system", methods=["POST"])
def system_exec():
    """
    Body example:
    { "cmd": "mybin.exe" }
    """
    data = request.get_json() or {}
    cmd = data.get("cmd")

    # ❌ Vulnerable: direct system() execution
    if cmd:
        res = os.system(cmd)  # Arbitrary command execution
        return jsonify({"status": "run", "code": res})
    
    return jsonify({"error": "no cmd provided"}), 400


#########################################
# 4. UNSAFE PLUGIN LOADER
#########################################
@app.route("/plugin/load", methods=["GET"])
def load_plugin():
    """
    Loads arbitrary shared libraries:
    /plugin/load?name=mylib.so
    """
    plugin = request.args.get("name")
    if not plugin:
        return jsonify({"error": "Missing plugin name"}), 400

    plugin_path = os.path.join(PLUGIN_DIR, plugin)

    # ❌ Vulnerable: blindly loading shared object files
    try:
        # Simulating unsafe plugin loading
        import ctypes
        lib = ctypes.CDLL(plugin_path)  # Arbitrary .so / .dll load
        return jsonify({"loaded": True, "plugin": plugin})
    except Exception as e:
        return jsonify({"loaded": False, "error": str(e)})


#########################################
# 5. VULNERABLE PATH-BASED SCRIPT RUNNER
#########################################
@app.route("/script/execute", methods=["GET"])
def execute_script():
    script_name = request.args.get("script")

    # ❌ Vulnerable: No validation → run arbitrary scripts
    try:
        output = subprocess.check_output(["python", script_name])
        return jsonify({
            "executed": True,
            "output": output.decode(errors="ignore")
        })
    except Exception as e:
        return jsonify({"executed": False, "error": str(e)})


#########################################
# 6. VULNERABLE CONFIG EXECUTION
#########################################
@app.route("/ci/run", methods=["POST"])
def ci_run():
    """
    Example insecure CI/CD config runner.
    {
        "config_path": "user_ci.yml"
    }
    """
    data = request.get_json() or {}
    config_path = data.get("config_path")

    # ❌ Vulnerable: execute commands extracted from a config file
    try:
        with open(config_path, "r") as f:
            lines = f.readlines()

        # Fake CI config:
        # run: mybinary
        for line in lines:
            if line.startswith("run:"):
                cmd = line.split("run:")[1].strip()
                # ❌ Vulnerable: arbitrary command execution from user config
                subprocess.call(cmd, shell=True)

        return jsonify({"status": "ci executed"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


#########################################
# 7. SERVE UPLOADED FILES (OPTIONAL)
#########################################
@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)


if __name__ == "__main__":
    app.run(port=5005, debug=True)
