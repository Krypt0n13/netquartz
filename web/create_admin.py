from models import User

# Benutzer anlegen
User.save_user("admin", "adminpass", True)
print("Admin-User erstellt.")
