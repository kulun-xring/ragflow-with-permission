#!/usr/bin/env python3
"""
RAGFlow 3-tier permission model test suite.
Covers: superadmin, teamadmin, teammember access control.
"""
import sys
import json

COOKIES = {}
BASE = "http://localhost:9380/api/v1"


def enc(pwd):
    import subprocess
    r = subprocess.run(
        ["docker", "exec", "docker-ragflow-cpu-1",
         "python3", "-c", "from api.utils.crypt import crypt; print(crypt('{}'))".format(pwd)],
        capture_output=True, text=True
    )
    return r.stdout.strip()


def login(email, password, label="login"):
    import subprocess, subprocess
    cookie_file = f"/tmp/cookie_{label}.txt"
    r = subprocess.run(
        ["curl", "-s", "-c", cookie_file, "-X", "POST", f"{BASE}/auth/login",
         "-H", "Content-Type: application/json",
         "-d", json.dumps({"email": email, "password": enc(password)})],
        capture_output=True, text=True
    )
    data = json.loads(r.stdout)
    COOKIES[label] = cookie_file
    if data.get("code") == 0:
        print(f"  ✓ {email} logged in")
    else:
        print(f"  ✗ {email} login failed: {data.get('message')}")
    return data.get("code") == 0


def api(method, path, body=None, cookies=None, label="login", extra_headers=None):
    import subprocess
    c = cookies or COOKIES.get(label) or "/tmp/cookie_default.txt"
    h = ["-b", c]
    if extra_headers:
        for k, v in extra_headers.items():
            h += ["-H", f"{k}: {v}"]
    if body:
        h += ["-H", "Content-Type: application/json"]
        h += ["-d", json.dumps(body)]
    r = subprocess.run(
        ["curl", "-s", "-X", method] + h + [f"{BASE}{path}"],
        capture_output=True, text=True
    )
    try:
        return json.loads(r.stdout)
    except:
        return {"code": 999, "message": r.stdout[:100]}


def test(name, expected_code, method, path, body=None, cookies=None, label="login", headers=None):
    r = api(method, path, body, cookies, label, headers)
    code = r.get("code", -1)
    ok = code == expected_code
    status = "✓" if ok else "✗"
    msg = r.get("message", "")[:60]
    print(f"  {status} {method} {path} → code={code} (expected={expected_code}) {msg}")
    return ok


def setup():
    print("\n=== SETUP: Create 2 teams, add members, assign admins ===")
    
    # Login as superadmin
    login("admin@ragflow.io", "admin", "superadmin")
    
    # Create team_a
    r = api("POST", "/tenants", {"name": "team_a"}, cookies=COOKIES["superadmin"], label="superadmin")
    assert r.get("code") == 0, f"Failed to create team_a: {r}"
    team_a_id = r["data"]["id"]
    print(f"  ✓ team_a created: {team_a_id[:20]}")
    
    # Create team_b
    r = api("POST", "/tenants", {"name": "team_b"}, cookies=COOKIES["superadmin"], label="superadmin")
    assert r.get("code") == 0, f"Failed to create team_b: {r}"
    team_b_id = r["data"]["id"]
    print(f"  ✓ team_b created: {team_b_id[:20]}")
    
    # Register members
    for email in ["alice@testperm.com", "bob@testperm.com", "carol@testperm.com"]:
        encpwd = enc("Test@1234")
        r = api("POST", "/users", {"email": email, "nickname": email.split("@")[0], "password": encpwd}, label="superadmin")
        if r.get("code") == 0:
            print(f"  ✓ Registered {email}")
        else:
            print(f"  - {email} already exists or error: {r.get('message','')[:50]}")
    
    # Add members to team_a
    for email in ["alice@testperm.com", "bob@testperm.com"]:
        r = api("POST", f"/tenants/{team_a_id}/users", {"email": email}, cookies=COOKIES["superadmin"], label="superadmin")
        print(f"  + {email} → team_a: code={r.get('code')}")
    
    # Add alice to team_b as admin
    r = api("POST", f"/tenants/{team_b_id}/users", {"email": "alice@testperm.com"}, cookies=COOKIES["superadmin"], label="superadmin")
    print(f"  + alice → team_b: code={r.get('code')}")
    
    # Get user IDs for admin appointment
    r = api("GET", f"/tenants/{team_a_id}/users", cookies=COOKIES["superadmin"], label="superadmin")
    alice_uid = None
    for u in r.get("data", []):
        if u["email"] == "alice@testperm.com":
            alice_uid = u["user_id"]
    
    if alice_uid:
        r = api("POST", f"/tenants/{team_a_id}/admins", {"user_id": alice_uid}, cookies=COOKIES["superadmin"], label="superadmin")
        print(f"  ✓ alice → teamadmin in team_a: code={r.get('code')}")
    
    return team_a_id, team_b_id


def test_superadmin(team_a_id, team_b_id):
    print("\n=== TEST: Superadmin can manage everything ===")
    
    # 1. Superadmin can create team
    r = api("POST", "/tenants", {"name": "superadmin_team"}, cookies=COOKIES["superadmin"], label="superadmin")
    assert test("superadmin creates team", 0, "POST", "/tenants", {"name": "s_temp_team"}, "superadmin"), "FAIL"
    
    # 2. Superadmin can list all teams
    r = api("GET", "/tenants", cookies=COOKIES["superadmin"], label="superadmin")
    ok = len(r.get("data", [])) >= 4  # superadmin's kingdom + team_a + team_b + temp
    print(f"  {'✓' if ok else '✗'} sees all teams: {len(r.get('data',[]))} total")
    
    # 3. Superadmin can assign teamadmin
    r = api("GET", f"/tenants/{team_a_id}/users", cookies=COOKIES["superadmin"], label="superadmin")
    carol_uid = None
    for u in r.get("data", []):
        if u["email"] == "carol@testperm.com":
            carol_uid = u["user_id"]
    
    if carol_uid:
        r = api("POST", f"/tenants/{team_a_id}/admins", {"user_id": carol_uid}, cookies=COOKIES["superadmin"], label="superadmin")
        print(f"  {'✓' if r.get('code')==0 else '✗'} carol → teamadmin in team_a: code={r.get('code')}")
    
    # 4. Superadmin can create KB in any team (via X-Tenant-Id)
    headers = {"X-Tenant-Id": team_a_id}
    r = api("POST", "/datasets", {"name": "superadmin_kb_team_a", "permission": "team"}, "superadmin", headers=headers)
    ok = r.get("code") == 0
    kb_id = r.get("data", {}).get("id", "") if ok else ""
    print(f"  {'✓' if ok else '✗'} superadmin creates KB in team_a: code={r.get('code')}")
    
    # 5. Superadmin can delete team
    r = api("GET", "/tenants", cookies=COOKIES["superadmin"], label="superadmin")
    temp_id = None
    for t in r.get("data", []):
        if t["name"] == "s_temp_team":
            temp_id = t["id"]
            break
    if temp_id:
        r = api("DELETE", f"/tenants/{temp_id}", cookies=COOKIES["superadmin"], label="superadmin")
        print(f"  {'✓' if r.get('code')==0 else '✗'} superadmin deletes team: code={r.get('code')}")
    
    return kb_id


def test_teamadmin(team_a_id, kb_id):
    print("\n=== TEST: Teamadmin (alice) manages team_a ===")
    
    # Login as alice
    login("alice@testperm.com", "Test@1234", "alice")
    
    # 1. Teamadmin can create KB in team_a
    headers = {"X-Tenant-Id": team_a_id}
    r = api("POST", "/datasets", {"name": "alice_kb_team_a", "permission": "team"}, "alice", headers=headers)
    ok = r.get("code") == 0
    alice_kb = r.get("data", {}).get("id", "") if ok else ""
    print(f"  {'✓' if ok else '✗'} alice (teamadmin) creates KB: code={r.get('code')}")
    
    # 2. Teamadmin can create chat
    r = api("POST", "/chats", {"name": "alice_chat"}, "alice", headers=headers)
    ok = r.get("code") == 0
    chat_id = r.get("data", {}).get("id", "") if ok else ""
    print(f"  {'✓' if ok else '✗'} alice (teamadmin) creates chat: code={r.get('code')}")
    
    # 3. Teamadmin can create agent/canvas
    r = api("POST", "/agents", {"title": "alice_agent", "canvas_type": "basic"}, "alice", headers=headers)
    ok = r.get("code") == 0
    agent_id = r.get("data", {}).get("id", "") if ok else ""
    print(f"  {'✓' if ok else '✗'} alice (teamadmin) creates agent: code={r.get('code')}")
    
    # 4. Teamadmin can update KB
    if alice_kb:
        r = api("PUT", f"/datasets/{alice_kb}", {"name": "alice_kb_updated"}, "alice", headers=headers)
        print(f"  {'✓' if r.get('code')==0 else '✗'} alice (teamadmin) updates KB: code={r.get('code')}")
    
    # 5. Teamadmin can delete KB
    if alice_kb:
        r = api("DELETE", f"/datasets/{alice_kb}", None, "alice", headers=headers)
        print(f"  {'✓' if r.get('code')==0 else '✗'} alice (teamadmin) deletes KB: code={r.get('code')}")


def test_teammember(team_a_id):
    print("\n=== TEST: Teammember (bob) can read but not write ===")
    
    # Login as bob
    login("bob@testperm.com", "Test@1234", "bob")
    
    # 1. Bob can LIST KBs in team_a (read access)
    headers = {"X-Tenant-Id": team_a_id}
    r = api("GET", "/datasets", None, "bob", headers=headers)
    ok = r.get("code") == 0
    print(f"  {'✓' if ok else '✗'} bob (teammember) lists KBs: code={r.get('code')}")
    
    # 2. Bob can LIST chats in team_a
    r = api("GET", "/chats", None, "bob", headers=headers)
    ok = r.get("code") == 0
    print(f"  {'✓' if ok else '✗'} bob (teammember) lists chats: code={r.get('code')}")
    
    # 3. Bob CANNOT create KB (no write permission)
    r = api("POST", "/datasets", {"name": "bob_kb"}, "bob", headers=headers)
    denied = r.get("code") in (403, 102, 401)
    print(f"  {'✓' if denied else '✗'} bob (teammember) cannot create KB: code={r.get('code')}")
    
    # 4. Bob CANNOT create chat
    r = api("POST", "/chats", {"name": "bob_chat"}, "bob", headers=headers)
    denied = r.get("code") in (403, 102, 401)
    print(f"  {'✓' if denied else '✗'} bob (teammember) cannot create chat: code={r.get('code')}")
    
    # 5. Bob CANNOT create agent
    r = api("POST", "/agents", {"title": "bob_agent", "canvas_type": "basic"}, "bob", headers=headers)
    denied = r.get("code") in (403, 102, 401)
    print(f"  {'✓' if denied else '✗'} bob (teammember) cannot create agent: code={r.get('code')}")
    
    # 6. Bob CANNOT update KB
    r = api("GET", "/datasets", None, "bob", headers=headers)
    kb_id = None
    for kb in r.get("data", {}).get("list", []):
        kb_id = kb.get("id")
        break
    if kb_id:
        r = api("PUT", f"/datasets/{kb_id}", {"name": "bob_attempt_update"}, "bob", headers=headers)
        denied = r.get("code") in (403, 102, 401)
        print(f"  {'✓' if denied else '✗'} bob (teammember) cannot update KB: code={r.get('code')}")


def test_cross_team(team_a_id, team_b_id):
    print("\n=== TEST: Cross-team access is denied ===")
    
    # Bob (member of team_a) tries to access team_b
    login("bob@testperm.com", "Test@1234", "bob")
    
    # 1. Bob cannot list KBs in team_b
    headers = {"X-Tenant-Id": team_b_id}
    r = api("GET", "/datasets", None, "bob", headers=headers)
    denied = r.get("code") in (403, 102, 401)
    print(f"  {'✓' if denied else '✗'} bob cannot access team_b KBs: code={r.get('code')}")
    
    # 2. Bob cannot create KB in team_b
    r = api("POST", "/datasets", {"name": "bob_cross"}, "bob", headers=headers)
    denied = r.get("code") in (403, 102, 401)
    print(f"  {'✓' if denied else '✗'} bob cannot create KB in team_b: code={r.get('code')}")
    
    # 3. Alice (admin of team_a, member of team_b) in team_b can write
    login("alice@testperm.com", "Test@1234", "alice")
    headers_b = {"X-Tenant-Id": team_b_id}
    r = api("POST", "/datasets", {"name": "alice_kb_team_b"}, "alice", headers=headers_b)
    ok = r.get("code") == 0
    print(f"  {'✓' if ok else '✗'} alice (admin of team_b) creates KB in team_b: code={r.get('code')}")


def test_teams_list_ui():
    print("\n=== TEST: Teams list for UI (tenant_id field) ===")
    
    login("admin@ragflow.io", "admin", "admin_login")
    r = api("GET", "/tenants", cookies=COOKIES["admin_login"], label="admin_login")
    
    has_tenant_id = all("tenant_id" in t for t in r.get("data", []))
    has_name = all("name" in t for t in r.get("data", []))
    print(f"  {'✓' if has_tenant_id else '✗'} All teams have tenant_id field")
    print(f"  {'✓' if has_name else '✗'} All teams have name field")
    
    # Show teams
    for t in r.get("data", []):
        print(f"    - {t['name']}: tenant_id={t.get('tenant_id','')[-12:]}, role={t.get('role','')}")
    
    # Also check /users/me/models (the dropdown selector)
    r2 = api("GET", "/users/me/models", cookies=COOKIES["admin_login"], label="admin_login")
    ok = "tenant_id" in r2.get("data", {})
    print(f"  {'✓' if ok else '✗'} /users/me/models has tenant_id: code={r2.get('code')}")


def main():
    print("=" * 60)
    print("RAGFlow 3-Tier Permission Model Test Suite")
    print("=" * 60)
    
    team_a_id, team_b_id = setup()
    kb_id = test_superadmin(team_a_id, team_b_id)
    test_teamadmin(team_a_id, kb_id)
    test_teammember(team_a_id)
    test_cross_team(team_a_id, team_b_id)
    test_teams_list_ui()
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()