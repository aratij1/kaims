from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.exc import OperationalError, TimeoutError as DatabaseTimeoutError
from fastapi import HTTPException

from common.database import AuditLogRecord, RoleRecord, UserRecord, UserSessionRecord


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_role_by_name(self, role_name: str) -> RoleRecord | None:
        result = await self.session.execute(select(RoleRecord).where(RoleRecord.name == role_name))
        return result.scalar_one_or_none()

    async def get_role(self, role_id: int) -> RoleRecord | None:
        result = await self.session.execute(select(RoleRecord).where(RoleRecord.id == role_id))
        return result.scalar_one_or_none()

    async def list_roles(self) -> list[RoleRecord]:
        result = await self.session.execute(select(RoleRecord).order_by(RoleRecord.id.asc()))
        return list(result.scalars().all())

    async def ensure_role(self, *, name: str, description: str, is_system_role: bool = True) -> RoleRecord:
        existing = await self.get_role_by_name(name)
        if existing:
            return existing
        role = RoleRecord(name=name, description=description, is_system_role=is_system_role)
        self.session.add(role)
        await self.session.flush()
        return role

    async def create_user(self, user: UserRecord) -> UserRecord:
        self.session.add(user)
        await self.session.flush()
        return user

    async def get_user(self, user_id: int) -> UserRecord | None:
        result = await self.session.execute(select(UserRecord).where(UserRecord.id == user_id))
        return result.scalar_one_or_none()

    async def get_user_by_username(self, username: str) -> UserRecord | None:
        result = await self.session.execute(select(UserRecord).where(UserRecord.username == username))
        return result.scalar_one_or_none()

    async def get_user_by_email(self, email: str) -> UserRecord | None:
        result = await self.session.execute(select(UserRecord).where(UserRecord.email == email))
        return result.scalar_one_or_none()

    async def list_users(
        self,
        *,
        page: int,
        page_size: int,
        search: str | None,
        role_id: int | None,
        status: str | None,
        sort_by: str,
        sort_dir: str,
    ) -> tuple[list[UserRecord], int]:
        base: Select[tuple[UserRecord]] = select(UserRecord)

        if search:
            token = f"%{search.strip()}%"
            base = base.where(
                or_(
                    UserRecord.username.ilike(token),
                    UserRecord.email.ilike(token),
                    UserRecord.first_name.ilike(token),
                    UserRecord.last_name.ilike(token),
                )
            )
        if role_id is not None:
            base = base.where(UserRecord.role_id == role_id)
        if status:
            base = base.where(UserRecord.status == status)

        sort_column_map = {
            "id": UserRecord.id,
            "username": UserRecord.username,
            "email": UserRecord.email,
            "created_at": UserRecord.created_at,
            "last_login": UserRecord.last_login,
        }
        sort_col = sort_column_map.get(sort_by, UserRecord.created_at)
        base = base.order_by(sort_col.desc() if sort_dir.lower() == "desc" else sort_col.asc())

        count_query = select(func.count()).select_from(base.subquery())
        total = int((await self.session.execute(count_query)).scalar_one())

        offset = max(0, (page - 1) * page_size)
        rows = (await self.session.execute(base.offset(offset).limit(page_size))).scalars().all()
        return list(rows), total

    async def create_session(
        self,
        *,
        user_id: int,
        jwt_id: str,
        login_time: datetime,
        expiry_time: datetime,
        ip_address: str | None,
        device: str | None,
        status: str,
    ) -> UserSessionRecord:
        rec = UserSessionRecord(
            user_id=user_id,
            jwt_id=jwt_id,
            login_time=login_time,
            expiry_time=expiry_time,
            ip_address=ip_address,
            device=device,
            status=status,
        )
        self.session.add(rec)
        await self.session.flush()
        return rec

    async def get_session_by_jti(self, jwt_id: str) -> UserSessionRecord | None:
        result = await self.session.execute(select(UserSessionRecord).where(UserSessionRecord.jwt_id == jwt_id))
        return result.scalar_one_or_none()

    async def revoke_session(self, jwt_id: str) -> None:
        rec = await self.get_session_by_jti(jwt_id)
        if rec:
            rec.status = "revoked"
            rec.updated_at = datetime.now(UTC)

    async def add_audit(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: dict,
        tenant_id: str = "default",
    ) -> None:
        self.session.add(
            AuditLogRecord(
                id=uuid4(),
                tenant_id=tenant_id or "default",
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                payload=payload,
            )
        )

    async def list_audit_logs(self, *, page: int, page_size: int, action: str | None) -> tuple[list[AuditLogRecord], int]:
        filters = [AuditLogRecord.action == action] if action else []
        # Sort narrow keys first. Sorting entire JSON payloads exhausted MySQL's
        # sort memory on real RCA audit records and made the audit workspace 500.
        count_query = select(func.count()).select_from(AuditLogRecord).where(*filters)
        total = int((await self.session.execute(count_query)).scalar_one())
        offset = max(0, (page - 1) * page_size)
        page_keys = select(AuditLogRecord.id, AuditLogRecord.created_at).where(*filters).order_by(
            AuditLogRecord.created_at.desc(), AuditLogRecord.id.desc(),
        ).offset(offset).limit(page_size).subquery()
        query = select(AuditLogRecord).join(page_keys, AuditLogRecord.id == page_keys.c.id).order_by(
            page_keys.c.created_at.desc(), page_keys.c.id.desc(),
        )
        rows = (await self.session.execute(query)).scalars().all()
        return list(rows), total


async def run_in_session(factory: async_sessionmaker[AsyncSession] | None, fn):
    if factory is None:
        raise HTTPException(status_code=503, detail="Database is disabled for this deployment")
    async with factory() as session:
        repo = UserRepository(session)
        try:
            result = await fn(repo)
            await session.commit()
            return result
        except (OperationalError, DatabaseTimeoutError) as exc:
            # A failed connection is infrastructure unavailability, not invalid
            # credentials. Never return driver messages or SQL to the client.
            try:
                await session.rollback()
            except OperationalError:
                pass  # Preserve the original connection failure.
            driver_args = getattr(getattr(exc, "orig", None), "args", ())
            code = driver_args[0] if driver_args else None
            if isinstance(exc, DatabaseTimeoutError) or code in {2002, 2003, 2006, 2013, 2055}:
                raise HTTPException(
                    status_code=503,
                    detail={"code": "authentication_store_unavailable",
                            "message": "Authentication is temporarily unavailable. Please try again shortly.",
                            "retryable": True},
                    headers={"Retry-After": "5"},
                ) from exc
            raise
        except Exception:
            await session.rollback()
            raise
