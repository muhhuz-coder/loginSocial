# tests/test_items.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
fake_secret_token = "coneofsilence"

def test_read_item():
    response = client.get("/items/foo", headers={"X-Token": fake_secret_token})
    assert response.status_code == 200
    assert response.json() == {
        "id": "foo",
        "title": "Foo",
        "description": "There goes my hero",
    }

def test_read_item_bad_token():
    response = client.get("/items/foo", headers={"X-Token": "badtoken"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid X-Token header"}

def test_read_nonexistent_item():
    response = client.get("/items/nonexistent", headers={"X-Token": fake_secret_token})
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

def test_create_item():
    new_item = {"id": "baz", "title": "Baz", "description": "Baz description"}
    response = client.post("/items/", headers={"X-Token": fake_secret_token}, json=new_item)
    assert response.status_code == 200
    assert response.json() == new_item

def test_create_item_existing():
    existing_item = {"id": "foo", "title": "Foo", "description": "There goes my hero"}
    response = client.post("/items/", headers={"X-Token": fake_secret_token}, json=existing_item)
    assert response.status_code == 409
    assert response.json() == {"detail": "Item already exists"}
