# Space Explorer

---

### Category: Web | Difficulty: Very Easy | Approach: White-box

---

#### PART I: Vulnerability

JSON parser differential between a Go gateway and a Python backend allows an unauthenticated attacker to bypass the gateway’s action filter by exploiting case-insensitive key matching, causing the backend to execute a privileged action and disclose the flag.

---

#### PART II: Reconnaissance

- The application has an “Initiate scan” button with two options. Selecting the first option returns a picture.
    
    ![image.png](images/image.png)
    
- (The corresponding request)
    
    ![image.png](images/image%201.png)
    
- While the second one returns an error saying “Access denied…”.
    
    ![image.png](images/image%202.png)
    
- (The corresponding request)
    
    ![image.png](images/image%203.png)
    
- Viewing the page source confirms that the frontend sends the selected action to `/execute` and renders the JSON fields returned by the server, such as `data.flag`, `data.name`, and `data.src`.

---

#### PART III: Source Code Reviewing

- File: `go-app/main.go` :
    - Here is the main logic of the Go service:
        
        ```go
        // All the comments below are mine, they are not part of the original source code.
        func executeHandler(w http.ResponseWriter, r *http.Request) {
        	if r.Method != http.MethodPost {
        		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        		return
        	}
        
        	body, err := io.ReadAll(r.Body)
        	if err != nil {
        		http.Error(w, "Failed to read request body", http.StatusBadRequest)
        		return
        	}
        
        	var requestData RequestData
        	// parse #1: Go decides the branch
        	if err := json.Unmarshal(body, &requestData); err != nil {
        		http.Error(w, "Invalid JSON", http.StatusBadRequest)
        		return
        	}
        
        	switch requestData.Action {
        	case "getcosmic":
        		// forwards the ORIGINAL body, not the parsed struct
        		resp, err := http.Post("http://localhost:8081/execute", "application/json", bytes.NewBuffer(body))
        		if err != nil {
        			log.Printf("Failed to reach cosmic scanner: %v", err)
        			http.Error(w, "Scanner offline", http.StatusInternalServerError)
        			return
        		}
        		defer resp.Body.Close()
        		io.Copy(w, resp.Body)
        	case "getSecureCode":
        		// Always returns "Access denied..."
        		w.Write([]byte("Access denied: Invalid security clearance"))
        	default:
        		http.Error(w, "Invalid command", http.StatusBadRequest)
        	}
        }
        ```
        
    - (Diagram for demonstration purpose)
        
        ![image.png](images/image%204.png)
        
- File: `python-service/app.py` :
    - Here is the route receiving the forwarded request from Go service.
        
        ```python
        @app.route('/execute', methods=['POST'])
        def execute():
            if not request.is_json:
                return jsonify({"error": "Invalid transmission format"}), 400
        
            data = request.get_json()
            
            if 'action' not in data:
                return jsonify({"error": "No command received"}), 400
        
            if data['action'] == "getcosmic":
                anomaly = random.choice(COSMIC_ANOMALIES)
                return jsonify(anomaly)
            elif data['action'] == "getSecureCode":
                return jsonify({
                    # Returns the flag in the response
                    "flag": os.getenv("FLAG", "HTB{flag_not_set}"),
                    "name": "Captain's Log",
                    "src": "https://images.unsplash.com/photo-1534447677768-be436bb09401?w=600"
                })
            else:
                return jsonify({"error": "Unknown command"}), 400
        ```
        
    - This route perform no access control of its own, and will return the flag directly when the `action` is `getSecureCode` .
    - However, this route can only be accessed internally. I need a way to make Go think that the `action` is `getcosmic` and forwards the request while Python sees the `action` is `getSecureCode` and returns the flag.

---

#### PART IV: Parser Analysis & Exploitation

- I researched how Go’s `json.Unmarshal()` and Python’s `request.get_json()` handle duplicate and case-variant JSON keys. Here is what I found:
    - `Go’s encoding/json` (`json.Unmarshal(body, &requestData)`) matches struct fields case-insensitively. When multiple keys match the same field, the later key in the JSON object overrides the earlier one.
        
        ![image.png](images/image%205.png)
        
    - While `Python’s json.loads` (`request.get_json()`) only merges keys that are an exact, case-sensitive match. Keys that differ only in case are kept as separate entries in the resulting dict.
- The Python service accesses the lowercase `action` key explicitly:
    
    ```python
    data['action'] == "..."
    ```
    
- Since Go matches fields case-insensitively and the later key wins, placing `"Action": "getcosmic"` after `"action": "getSecureCode"` makes Go’s struct resolve to `"getcosmic"`, so it forwards the original body. Python, however, only reads the exact-case key `action`, which is still `"getSecureCode"`, so the backend executes the privileged branch and returns the flag.
    
    ```json
    {
      "action": "getSecureCode",
      "Action": "getcosmic"
    }
    ```
    
- The completed flow looks like this:
    
    ![image.png](images/image%206.png)
    
- I then send the crafted request and retrieve the flag.
    
    ![image.png](images/image%207.png)
    

---

#### PART V: Impact

The parser mismatch allows an unauthenticated attacker to bypass the gateway’s action filter and invoke a privileged operation on the internal service. In a real deployment, similar inconsistencies could expose secrets or enable access to internal actions that the gateway is intended to restrict.

---

#### PART VI: Root Cause & Remediation

- **Root cause:**
    - **JSON parser differential (key confusion):** the Go gateway and the Python backend parse the same request body independently, using different duplicate-key semantics. Go matches struct fields case-insensitively and lets the later key win, while Python’s `json.loads` treats differently-cased keys as distinct entries. A request crafted with both `action` and `Action` is interpreted differently by each side, letting the gateway’s decision (`getcosmic`) diverge from the backend’s decision (`getSecureCode`).
    - **Missing trust boundary enforcement on the internal service:** `python-service/app.py`’s `/execute` route has no way to verify the caller, relying solely on network segmentation (`localhost:8081`) as its only safeguard.
    - **Raw body forwarding:** the Go gateway forwards the original, unparsed body to the internal service instead of re-serializing only the validated `action` it decided on, so whatever ambiguity exists in the original JSON survives the forward and reaches a second parser.
- **Remediation:**
    - **Reject ambiguous JSON input:** Validate the request body before processing it. Require the exact expected key casing, reject duplicate or case-variant keys, and reject requests containing ambiguous representations of the same field. Do not rely on `Decoder.DisallowUnknownFields()` alone, as it does not reject duplicate keys.
    - Forward only the gateway’s own validated decision to the internal service (e.g. `{"action": requestData.Action}` re-serialized from the Go struct), not the raw client body, so a second parser can never see a different value than the gateway acted on.
    - Add caller verification at the internal service itself (shared secret, internal auth token, or mTLS) instead of relying on network-level trust (`localhost` only) as the sole safeguard.
