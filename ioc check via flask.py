from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Define critical paths
critical_paths = {
    "Linux": [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin"
    ],
    "Windows": [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Program Files (x86)\Common Files",
        r"C:\Program Files\Common Files",
        r"C:\Program Files (x86)",
        r"C:\Program Files"
    ]
}

# Define a function to check critical paths
def check_critical_paths(critical_paths_list):
    present_paths = []
    not_present_paths = []

    for path in critical_paths_list:
        if os.path.exists(path):
            present_paths.append(path)
        else:
            not_present_paths.append(path)

    return present_paths, not_present_paths

# Define an API endpoint to receive and store IOCs
@app.route("/add_ioc", methods=["POST"])
def add_ioc():
    ioc = request.json
    # Store the received IOC in the database or file
    # ...

    return jsonify({"message": "IOC added successfully"})

# Define an API endpoint to retrieve stored IOCs
@app.route("/get_iocs", methods=["GET"])
def get_iocs():
    # Retrieve stored IOCs from the database or file
    # ...

    return jsonify({"iocs": iocs})

# Define an API endpoint to check the critical paths
@app.route("/check_critical_paths", methods=["GET"])
def check_critical_paths_endpoint():
    os_type = request.args.get("os_type", "Linux")
    critical_paths_list = critical_paths.get(os_type, [])

    present_paths, not_present_paths = check_critical_paths(critical_paths_list)

    return jsonify({
        "present_paths": present_paths,
        "not_present_paths": not_present_paths
    })

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
