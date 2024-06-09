import pytest
from app import app, db
from models import User

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

def test_create_user(client):
    response = client.post('/', json={
        'username': 'testuser',
        'password': 'password123'
    })
    assert response.status_code == 201
    assert b"User created successfully" in response.data

def test_login_user(client):
    client.post('/', json={
        'username': 'testuser',
        'password': 'password123'
    })
    response = client.put('/', json={
        'username': 'testuser',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert b"Login successful" in response.data

def test_change_password(client):
    client.post('/', json={
        'username': 'testuser',
        'password': 'password123'
    })
    response = client.put('/trocasenha', json={
        'username': 'testuser',
        'current_password': 'password123',
        'new_password': 'newpassword123'
    })
    assert response.status_code == 200
    assert b"Password changed successfully" in response.data

def test_get_blocked_users(client):
    response = client.get('/bloqueados')
    assert response.status_code == 200
