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

PREFIX_HANDLERS = {

    "/api/health": allow_public,
    "/qr/health":  allow_public,


    "/api/auth": allow_public,

    "GET:/api/users/me/stats":              require_user,
    "GET:/api/users/me":                    require_user,
    "PUT:/api/users/me":                    require_user,
    "GET:/api/users/{user_id}/points-summary": require_manager,
    "GET:/api/users/{user_id}":             require_user,
    "PUT:/api/users/{user_id}":             require_manager,
    "GET:/api/users":                       require_user,
    "POST:/api/users":                      require_manager,
    "DELETE:/api/users/{user_id}":          require_admin,

    "GET:/api/rbac/roles":                              require_admin,
    "GET:/api/rbac/users/{user_id}/assignments":        require_admin,
    "POST:/api/rbac/assign-role":                       require_admin,
    "DELETE:/api/rbac/assignments/{assignment_id}":     require_admin,
    "/api/rbac":                                        require_admin,

    "POST:/api/units":                              require_admin,
    "GET:/api/units":                               allow_public,
    "GET:/api/units/{unit_id}":                     allow_public,
    "PUT:/api/units/{unit_id}":                     require_staff,
    "DELETE:/api/units/{unit_id}":                  require_admin,
    "POST:/api/units/{unit_id}/members":            require_staff,
    "GET:/api/units/{unit_id}/members":             require_staff,
    "DELETE:/api/units/{unit_id}/members/{user_id}":require_staff,

    "POST:/api/semesters":              require_admin,
    "GET:/api/semesters/current":       allow_public,
    "GET:/api/semesters":               allow_public,
    "PUT:/api/semesters/{semester_id}": require_admin,
    "/api/semesters":                   require_admin,

    "GET:/api/events/valid":                        allow_public,
    "GET:/api/events/me/registrations":             require_user,
    
    # Event Registrations
    "POST:/api/events/{event_id}/register_public_event": require_user,
    "DELETE:/api/events/{event_id}/register":       require_user,
    "GET:/api/events/{event_id}/registrations":     require_admin,
    "GET:/api/events/{event_id}/my-registration":   require_user,
    
    # Events Management
    "GET:/api/events/{event_id}":                   allow_public,
    "PUT:/api/events/{event_id}":                   require_manager,
    "DELETE:/api/events/{event_id}":                require_manager,
    
    "POST:/api/events":                             require_manager,
    "GET:/api/events":                              require_manager,
    "/api/events":                                  require_manager,   # fallback

    "POST:/api/unit-events":                        require_manager,
    "GET:/api/unit-events/all":                     require_manager,
    "GET:/api/unit-events/my":                      require_staff,
    "GET:/api/unit-events/{event_id}":              require_manager,
    "PUT:/api/unit-events/{event_id}":              require_manager,
    "DELETE:/api/unit-events/{event_id}":           require_manager,
    "/api/unit-events":                             require_manager,

    "POST:/api/event-promotions":                   require_staff,
    "GET:/api/event-promotions/admin":              require_manager,
    "GET:/api/event-promotions/my-unit":            require_staff,
    "GET:/api/event-promotions/public":             allow_public,
    "GET:/api/event-promotions/{id}":               allow_public,
    "PUT:/api/event-promotions/{id}/status":        require_manager,
    "PUT:/api/event-promotions/{id}":               require_staff,
    "DELETE:/api/event-promotions/{id}":            require_staff,
    "/api/event-promotions":                        require_staff,

    "GET:/api/unit-event-submissions/HTTT/all":             require_manager,
    "POST:/api/unit-event-submissions/status":              require_manager,
    "GET:/api/unit-event-submissions/HTSK/list":            require_manager,
    "GET:/api/unit-event-submissions/HTSK/student/overview":require_user,
    "POST:/api/unit-event-submissions/HTSK/student/register": require_user,
    "DELETE:/api/unit-event-submissions/HTSK/student/register": require_user,
    
    "POST:/api/unit-event-submissions/HTTT":                require_staff,
    "GET:/api/unit-event-submissions/HTTT":                 require_staff,
    "PUT:/api/unit-event-submissions/HTTT":                 require_staff,
    "POST:/api/unit-event-submissions/HTSK":                require_staff,
    "GET:/api/unit-event-submissions/HTSK":                 require_staff,
    "PUT:/api/unit-event-submissions/HTSK":                 require_staff,
    "/api/unit-event-submissions":                          require_staff,

    "GET:/api/reports/all":                                         require_manager,
    "GET:/api/reports/export/summary":                              require_manager,
    "GET:/api/reports/{report_id}/export/detail":                   require_staff,
    "GET:/api/reports/{report_id}":                                 require_staff,
    "POST:/api/reports/{report_id}/internal-events":                require_staff,
    "PUT:/api/reports/{report_id}/internal-events/{event_id}":      require_staff,
    "DELETE:/api/reports/{report_id}/internal-events/{event_id}":   require_staff,
    "POST:/api/reports/{report_id}/submit":                         require_staff,
    "POST:/api/reports/{report_id}/status":                         require_manager,
    "GET:/api/reports":                                             require_staff,
    "/api/reports":                                                 require_staff,

    "/api/upload": require_user,

    "/qr/attendance/events":       require_manager,
    "/qr/attendance/unit-events":  require_manager,
    "/qr/attendance/scan":         require_user,
    "/qr/attendance/code":         require_user,

    "/api/docs":         allow_public,
    "/api/openapi.json": allow_public,
    "/qr/docs":         allow_public,
    "/qr/openapi.json":  allow_public,

}
