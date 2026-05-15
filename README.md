# api_gateway

`api_gateway` là service gateway dùng Caddy cho môi trường local.

## Vai trò

- Nhận traffic public từ client local.
- Route `/api/*` vào `be-service-api`.
- Route `/qr/*` vào `qr-service-api` và rewrite thành `/api/*` trước khi forward vào service đích.
- Forward các header `X-Forwarded-*` để service phía sau biết thông tin request gốc.
- Giữ auth và RBAC ở từng service, không đặt business logic ở gateway.

## File chính

- [Caddyfile](/d:/TTCS/api_gateway/Caddyfile)
