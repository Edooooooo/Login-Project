from app import db


class Phone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    phone_code = db.Column(db.Integer, nullable=False)
    number = db.Column(db.String(10), nullable=False)