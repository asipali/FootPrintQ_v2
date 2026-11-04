import os
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel
from app.models.user import UserModel
from app.services.target_authorization import (
    verify_target_authorization,
    classify_target,
    is_target_in_investigation_scope
)

db_url = os.getenv('DATABASE_URL', 'mssql+pyodbc://@localhost\\SQLEXPRESS/footprintiq?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes')
engine = create_engine(db_url)

with Session(engine) as db:
    inv = db.get(InvestigationModel, 'inv-0fabf5f0690244e089b55661a273ee8a')
    owner = db.get(UserModel, inv.owner_user_id) if inv else None
    admin = db.query(UserModel).filter(UserModel.role == 'administrator').first()

    print("=================================================================")
    print("INVESTIGATION TARGET & AUTHORIZATION RECORD AUDIT")
    print("=================================================================")
    print(f"Investigation ID: {inv.id}")
    print(f"Title: {inv.name}")
    print(f"Status: {inv.status}")
    print(f"Owner: {owner.username if owner else 'None'} ({inv.owner_user_id})")
    print(f"Owned Domains: {inv.owned_domains}")
    print(f"Approved IPs: {inv.approved_ips}")
    print(f"Approved CIDRs: {inv.approved_cidrs}")
    print(f"Active Targets: {inv.active_targets}")
    print()

    authzs = db.query(TargetAuthorizationModel).filter(TargetAuthorizationModel.investigation_id == inv.id).all()
    print(f"Found {len(authzs)} explicit TargetAuthorization records:")
    for a in authzs:
        print(f" - [{a.id}] Target: {a.target} (Type: {a.target_type}), Ops: {a.allowed_operations}, Valid: {a.valid_from} to {a.valid_to}, Revoked: {a.is_revoked}")
    print()

    # Test Matrix across targets and operations
    test_targets = [
        ("IP (Approved & Explicitly Authorized)", "192.168.56.107"),
        ("IP (In CIDR 192.168.56.0/24 but not explicitly authorized)", "192.168.56.150"),
        ("IP (Unapproved outside scope)", "10.0.0.1"),
        ("CIDR (Approved in investigation scope)", "192.168.56.0/24"),
        ("CIDR (Unapproved outside scope)", "10.0.0.0/24"),
        ("Domain (In owned_domains but no explicit TargetAuthorization)", "www.mozilla.org"),
        ("Subdomain of owned domain", "test.www.mozilla.org"),
        ("Domain (Unapproved outside scope)", "unauthorized.example"),
        ("URL (Malformed / invalid target format)", "https://www.mozilla.org/events"),
    ]

    operations = ["RECON_PASSIVE", "SCAN_ACTIVE", "SCAN_VULN"]

    actor = owner or admin
    print(f"Evaluating as Actor: {actor.username} (Role: {actor.role})")
    print("=" * 80)
    for desc, target in test_targets:
        print(f"\nTARGET: {target} ({desc})")
        target_type = classify_target(target)
        in_scope, scope_msg = is_target_in_investigation_scope(inv, target)
        print(f"  Classification: {target_type}")
        print(f"  In Scope Check: in_scope={in_scope} -> {scope_msg}")
        for op in operations:
            is_authz, reason = verify_target_authorization(
                db=db,
                investigation=inv,
                target=target,
                operation=op,
                actor_user=actor
            )
            status_str = "APPROVED" if is_authz else "REJECTED"
            print(f"    [{status_str}] Op: {op:<14} -> {reason}")

