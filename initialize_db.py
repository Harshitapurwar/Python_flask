from app import app, db
from models import User, UserProfile,WorkerProfile

with app.app_context():
    # Create the database tables
    db.create_all()
    print("Database tables created successfully.")

    # Query and print all users
    users = User.query.all()
    for user in users:
        print(f'User ID: {user.id}, Name: {user.name}, Email: {user.email}, Password: {user.password}')

    # Query and print all user profiles
    profiles = UserProfile.query.all()
    for profile in profiles:
        print(f'Profile ID: {profile.id}, First Name: {profile.fname}, Last Name: {profile.lname}, Phone: {profile.phone}, Street: {profile.street}, City: {profile.city}, Postal Code: {profile.postal_code}, State: {profile.state}, Country: {profile.country}, Avatar: {profile.avatar}')

    workers = WorkerProfile.query.all()
    for worker in workers:
        print(f'Worker ID: {worker.id}, First Name: {worker.fname}, Last Name: {worker.lname}, Phone: {worker.phone}, Street: {worker.street}, City: {worker.city}, Postal Code: {worker.postal_code}, State: {worker.state}, Country: {worker.country}, Avatar: {worker.avatar}, Service Type: {worker.service_type}')
