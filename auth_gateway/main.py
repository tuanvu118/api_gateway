import json
from fastapi import FastAPI, Header, Request, HTTPException, status
from fastapi.responses import Response
from security import get_current_user, PREFIX_HANDLERS, require_user

app = FastAPI(title="Auth Gateway")

def find_handler(method: str, path: str):
    # Normalize path (remove trailing slash for matching unless it's just "/")
    norm_path = path.rstrip("/") if path != "/" else "/"
    
    # Try exact matches first
    # 1. Exact Method:Path
    method_path = f"{method}:{norm_path}"
    if method_path in PREFIX_HANDLERS:
        return PREFIX_HANDLERS[method_path]
        
    # 2. Exact Path
    if norm_path in PREFIX_HANDLERS:
        return PREFIX_HANDLERS[norm_path]

    # Prefix matching (fallback)
    def path_len(k):
        return len(k.split(":", 1)[1]) if ":" in k else len(k)
        
    # Sort prefixes by length of the path descending
    sorted_prefixes = sorted(
        [k for k in PREFIX_HANDLERS.keys() if k.endswith("/") or ":" in k or "/" in k], 
        key=path_len, 
        reverse=True
    )
    
    # 3. Try Method:Path prefix matching
    # We want to match segments, so we add a trailing slash if needed
    for prefix in sorted_prefixes:
        if ":" in prefix:
            p_method, p_path = prefix.split(":", 1)
            if p_method == method and (path == p_path or path.startswith(p_path + "/")):
                return PREFIX_HANDLERS[prefix]
            
    # 4. Try Path only prefix matching
    for prefix in sorted_prefixes:
        if ":" not in prefix:
            if path == prefix or path.startswith(prefix + "/"):
                return PREFIX_HANDLERS[prefix]
                
    # Default fallback: if it's under /api/ or /qr/, default to require_user?
    # Actually, better to be strict.
    return None

@app.get("/verify")
@app.post("/verify")
@app.put("/verify")
@app.delete("/verify")
@app.patch("/verify")
@app.options("/verify")
async def verify(
    request: Request,
    authorization: str = Header(None),
    x_unit_id: str | None = Header(None, alias="X-Unit-Id"),
    x_forwarded_uri: str = Header(..., alias="X-Forwarded-Uri"),
    x_forwarded_method: str = Header(..., alias="X-Forwarded-Method")
):
    # Extract original path from X-Forwarded-Uri (which might include query params)
    original_path = x_forwarded_uri.split("?")[0]
    
    handler = find_handler(x_forwarded_method, original_path)
    
    from security import allow_public
    
    current_user = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        try:
            current_user = get_current_user(token)
        except HTTPException as e:
            if handler != allow_public:
                raise e
    elif handler != allow_public:
        # If it's not a public endpoint, we need a token
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Authorization header")
    
    if handler:
        # This will raise an exception if unauthorized
        handler(current_user, x_unit_id)
    else:
        # Safe default: if not in PREFIX_HANDLERS, deny
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"No authorization handler defined for {x_forwarded_method} {original_path}")
        
    # Return 200 OK with user info in headers
    if current_user:
        roles_json = json.dumps([r.model_dump() for r in current_user.roles])
        
        return Response(
            status_code=200,
            headers={
                "X-User-Id": current_user.sub,
                "X-User-Email": current_user.email or "",
                "X-User-Roles": roles_json,
                "X-Unit-Id": x_unit_id or ""
            }
        )
    else:
        return Response(status_code=200)

@app.get("/health")
async def health():
    return {"status": "ok"}
