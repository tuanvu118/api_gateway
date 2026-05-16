import os
from typing import Optional, List

from fastapi import HTTPException, status
from jose import JWTError, jwt
from pydantic import BaseModel

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_SECRET_KEY")
ALGORITHM = "HS256"


class UnitRole(BaseModel):
    unit_id: str
    roles: List[str]


class TokenData(BaseModel):
    sub: str
    email: Optional[str] = None
    roles: List[UnitRole] = []


def get_current_user(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token: missing sub")
        email = payload.get("email")
        roles_raw = payload.get("roles", [])
        roles = [UnitRole(**r) for r in roles_raw]
        return TokenData(sub=sub, email=email, roles=roles)
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")


def _has_role_in_unit(current_user: TokenData, allowed_roles: list, unit_id: str) -> bool:
    if not current_user: return False
    for unit_role in current_user.roles:
        if unit_role.unit_id == unit_id:
            return any(r in unit_role.roles for r in allowed_roles)
    # ADMIN có quyền ở mọi đơn vị
    return any("ADMIN" in unit_role.roles for unit_role in current_user.roles)


def require_admin(current_user: TokenData, unit_id: str = None) -> TokenData:
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token required")
    has_admin = any("ADMIN" in unit_role.roles for unit_role in current_user.roles)
    if not has_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="ADMIN role required")
    return current_user

def require_manager(current_user: TokenData, unit_id: str = None) -> TokenData:
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token required")
    if unit_id is None:
        has_manager_role = any("ADMIN" in unit_role.roles or "MANAGER" in unit_role.roles for unit_role in current_user.roles)
        if not has_manager_role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MANAGER or higher required")
    else:
        if not _has_role_in_unit(current_user, ["ADMIN", "MANAGER"], unit_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MANAGER or higher required for unit")
    return current_user

def require_staff(current_user: TokenData, unit_id: str = None) -> TokenData:
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token required")
    if unit_id is None:
        # Fallback if no unit_id provided in header, but user is global admin/manager
        has_global_manager = any("ADMIN" in unit_role.roles or "MANAGER" in unit_role.roles for unit_role in current_user.roles)
        if has_global_manager: return current_user
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="X-Unit-Id header is required")
    if not _has_role_in_unit(current_user, ["ADMIN", "MANAGER", "STAFF"], unit_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="STAFF or higher required for unit")
    return current_user

def require_user(current_user: TokenData, unit_id: str = None) -> TokenData:
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token required")
    return current_user

def allow_public(current_user: Optional[TokenData], unit_id: str = None) -> Optional[TokenData]:
    return current_user

# =============================================================================
# PREFIX_HANDLERS
# Key format: "METHOD:/path" (method-specific) hoặc "/path" (mọi method)
# Prefix dài hơn (theo path) được ưu tiên khớp trước (sorted by path-length desc)
# Nguồn: đối chiếu trực tiếp với be_ttcs/routers/*.py
# =============================================================================
PREFIX_HANDLERS = {

    # -------------------------------------------------------------------------
    # System / Health
    # -------------------------------------------------------------------------
    "/api/health": allow_public,
    "/qr/health":  allow_public,

    # -------------------------------------------------------------------------
    # Auth Router  (prefix="/auth" → /api/auth)
    # POST /api/auth/login    → allow_public
    # POST /api/auth/refresh  → allow_public
    # POST /api/auth/logout   → allow_public
    # -------------------------------------------------------------------------
    "/api/auth": allow_public,

    # -------------------------------------------------------------------------
    # Users Router  (prefix="/users" → /api/users)
    # GET  /api/users/me/stats       → require_user
    # GET  /api/users/me             → require_user
    # PUT  /api/users/me             → require_user  (cập nhật bản thân)
    # GET  /api/users                → require_user  (list_visible_users – service tự lọc)
    # GET  /api/users/{id}           → require_user
    # GET  /api/users/{id}/points-summary → require_manager (require_admin_or_manager_global)
    # POST /api/users                → require_manager (require_admin_or_manager_global)
    # PUT  /api/users/{id}           → require_manager (require_admin_or_manager_global)
    # -------------------------------------------------------------------------
    "/api/users/me/stats":      require_user,
    "/api/users/me":            require_user,
    "POST:/api/users":          require_manager,
    "GET:/api/users":           require_user,
    "PUT:/api/users":           require_manager,
    "DELETE:/api/users":        require_admin,

    # -------------------------------------------------------------------------
    # RBAC Router  (prefix="/rbac" → /api/rbac)
    # GET    /api/rbac/roles                     → require_admin
    # GET    /api/rbac/users/{id}/assignments    → require_admin
    # POST   /api/rbac/assign-role               → require_admin
    # DELETE /api/rbac/assignments/{id}          → require_admin
    # -------------------------------------------------------------------------
    "/api/rbac": require_admin,

    # -------------------------------------------------------------------------
    # Units Router  (prefix="/units" → /api/units)
    # GET    /api/units               → allow_public  (không có Depends)
    # GET    /api/units/{id}          → allow_public  (không có Depends)
    # GET    /api/units/{id}/members  → require_user
    # POST   /api/units/{id}/members  → require_user
    # DELETE /api/units/{id}/members  → require_user
    # POST   /api/units               → require_admin
    # PUT    /api/units/{id}          → require_user  (service kiểm tra thêm)
    # DELETE /api/units/{id}          → require_admin
    # -------------------------------------------------------------------------
    "/api/units": allow_public,   # GET list & GET detail đều public; write endpoints dùng Depends ở router

    # -------------------------------------------------------------------------
    # Semesters Router  (prefix="/semesters" → /api/semesters)
    # GET  /api/semesters         → allow_public  (không có Depends)
    # GET  /api/semesters/current → allow_public  (không có Depends)
    # POST /api/semesters         → require_admin  (require_global_admin)
    # PUT  /api/semesters/{id}    → require_admin  (require_global_admin)
    # -------------------------------------------------------------------------
    "GET:/api/semesters":       allow_public,
    "/api/semesters":           require_admin,

    # -------------------------------------------------------------------------
    # Public Events Router  (prefix="/events" → /api/events)
    # GET  /api/events/valid      → allow_public  (không có Depends)
    # GET  /api/events/{id}       → allow_public  (không có Depends)
    # GET  /api/events/           → require_manager
    # POST /api/events/           → require_manager
    # PUT  /api/events/{id}       → require_manager
    # DELETE /api/events/{id}     → require_manager
    # -------------------------------------------------------------------------
    "/api/events/valid":        allow_public,

    # -------------------------------------------------------------------------
    # Event Registration Router  (prefix="/events" → /api/events) — cùng prefix
    # GET    /api/events/me/registrations            → require_user
    # POST   /api/events/{id}/register_public_event  → require_user
    # POST   /api/events/{id}/register_unit_event    → require_user
    # DELETE /api/events/{id}/register               → require_user
    # GET    /api/events/{id}/my-registration        → require_user
    # GET    /api/events/{id}/registrations          → require_admin
    # -------------------------------------------------------------------------
    "/api/events/me/registrations": require_user,
    # GET /{id} cũng public (xem chi tiết sự kiện), còn GET / cần manager
    "GET:/api/events":          allow_public,
    # POST/PUT/DELETE → manager; GET / (list) → manager
    "POST:/api/events":         require_manager,
    "PUT:/api/events":          require_manager,
    "DELETE:/api/events":       require_manager,
    "/api/events":              require_manager,   # fallback

    # -------------------------------------------------------------------------
    # Unit Events Router  (prefix="/unit-events" → /api/unit-events)
    # GET  /api/unit-events/all   → require_manager  (Quyền: VPĐ hoặc ADMIN)
    # GET  /api/unit-events/my    → require_staff    (Quyền: Quản lý đơn vị)
    # GET  /api/unit-events/{id}  → require_manager  (Quyền: VPĐ hoặc ADMIN hoặc STAFF)
    # POST /api/unit-events/      → require_manager
    # PUT  /api/unit-events/{id}  → require_manager
    # DELETE /api/unit-events/{id}→ require_manager  (Quyền: VPĐ hoặc ADMIN)
    # -------------------------------------------------------------------------
    "/api/unit-events/all":     require_manager,
    "/api/unit-events/my":      require_staff,
    "/api/unit-events":         require_manager,

    # -------------------------------------------------------------------------
    # Event Promotions Router  (prefix="/event-promotions" → /api/event-promotions)
    # GET  /api/event-promotions/public   → allow_public  (không có Depends)
    # GET  /api/event-promotions/{id}     → allow_public  (không có Depends)
    # GET  /api/event-promotions/admin    → require_manager
    # GET  /api/event-promotions/my-unit  → require_staff
    # POST /api/event-promotions          → require_staff
    # PUT  /api/event-promotions/{id}     → require_staff
    # PUT  /api/event-promotions/{id}/status → require_manager
    # DELETE /api/event-promotions/{id}   → require_staff
    # -------------------------------------------------------------------------
    "/api/event-promotions/public":         allow_public,
    "/api/event-promotions/admin":          require_manager,
    "/api/event-promotions/my-unit":        require_staff,
    "GET:/api/event-promotions":            allow_public,   # GET /{id} là public
    "PUT:/api/event-promotions":            require_staff,  # PUT /{id} → staff; /{id}/status → manager (handled same)
    "/api/event-promotions":                require_staff,

    # -------------------------------------------------------------------------
    # Unit Event Submissions Router  (prefix="/unit-event-submissions" → /api/unit-event-submissions)
    # GET  /api/unit-event-submissions/HTTT/all                  → require_manager
    # POST /api/unit-event-submissions/status                    → require_manager
    # GET  /api/unit-event-submissions/HTSK/list                 → require_manager
    # GET  /api/unit-event-submissions/HTSK/student/overview     → require_user
    # POST /api/unit-event-submissions/HTSK/student/register     → require_user
    # DELETE /api/unit-event-submissions/HTSK/student/register   → require_user
    # POST /api/unit-event-submissions/HTTT                      → require_staff
    # GET  /api/unit-event-submissions/HTTT                      → require_staff
    # PUT  /api/unit-event-submissions/HTTT                      → require_staff
    # POST /api/unit-event-submissions/HTSK                      → require_staff
    # GET  /api/unit-event-submissions/HTSK                      → require_staff
    # PUT  /api/unit-event-submissions/HTSK                      → require_staff
    # -------------------------------------------------------------------------
    "/api/unit-event-submissions/HTTT/all":             require_manager,
    "/api/unit-event-submissions/status":               require_manager,
    "/api/unit-event-submissions/HTSK/list":            require_manager,
    "/api/unit-event-submissions/HTSK/student/overview":require_user,
    "/api/unit-event-submissions/HTSK/student/register":require_user,
    "/api/unit-event-submissions":                      require_staff,

    # -------------------------------------------------------------------------
    # Reports Router  (prefix="/reports" → /api/reports)
    # GET  /api/reports/all                              → require_manager
    # GET  /api/reports/export/summary                   → require_manager
    # GET  /api/reports/                                 → require_staff
    # GET  /api/reports/{id}                             → require_user  (get_current_user)
    # POST /api/reports/{id}/internal-events             → require_staff
    # PUT  /api/reports/{id}/internal-events/{event_id}  → require_staff
    # DELETE /api/reports/{id}/internal-events/{event_id}→ require_staff
    # POST /api/reports/{id}/submit                      → require_staff
    # POST /api/reports/{id}/status                      → require_manager
    # GET  /api/reports/{id}/export/detail               → require_user  (get_current_user)
    # -------------------------------------------------------------------------
    "/api/reports/all":             require_manager,
    "/api/reports/export/summary":  require_manager,
    "GET:/api/reports":             require_user,    # GET / → staff (service lọc); GET /{id} → user
    "/api/reports":                 require_staff,

    # -------------------------------------------------------------------------
    # Upload Router  (prefix="/upload" → /api/upload)
    # POST /api/upload → require_user
    # -------------------------------------------------------------------------
    "/api/upload": require_user,

    # -------------------------------------------------------------------------
    # QR Service Routers  (/qr)
    # POST /qr/attendance         → require_staff  (tạo/mở session điểm danh)
    # POST /qr/manual-attendance  → require_staff  (điểm danh thủ công)
    # POST /qr/checkin            → require_user   (sinh viên tự check-in)
    # -------------------------------------------------------------------------
    "/qr/attendance/events":       require_manager,
    "/qr/attendance/unit-events":  require_manager,
    "/qr/attendance/scan":         require_user,
    "/qr/attendance/code":         require_user,


    # Cho phép xem tài liệu API (Swagger) công khai
    "/api/docs":         allow_public,
    "/api/openapi.json": allow_public,
    "/qr/docs":         allow_public,
    "/qr/openapi.json":  allow_public,

}
