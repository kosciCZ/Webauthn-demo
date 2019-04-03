from pywarp.backends import CredentialStorageBackend
from pywarp import Credential


class InvalidChallengeType(Exception):
    pass


class SQLliteBackend(CredentialStorageBackend):
    def __init__(self, db, user_model):
        self.database_client = db
        self.user_model = user_model

    def get_or_create(self, email):
        user = self.user_model.query.filter_by(email=email).first()
        if user is None:
            user = self.user_model(email)
            self.database_client.session.add(user)
            self.database_client.session.commit()
        return user

    def get_credential_by_email(self, email):
        user_record = self.user_model.query.filter_by(email=email).first()
        return Credential(credential_id=user_record.credential_id,
                          credential_public_key=user_record.public_key)

    def save_credential_for_user(self, email, credential):
        user_record = self.user_model.query.filter_by(email=email).first()
        user_record.credential_id = credential.id
        user_record.public_key = bytes(credential.public_key)
        self.database_client.session.commit()

    def save_challenge_for_user(self, email, challenge, type):
        user = self.get_or_create(email)
        user_record = self.user_model.query.filter_by(email=email).first()
        if type == "registration":
            user_record.registration_challenge = challenge
        elif type == "authentication":
            user_record.authentication_challenge = challenge
        else:
            raise InvalidChallengeType
        self.database_client.session.commit()

    def get_challenge_for_user(self, email, type):
        user_record = self.user_model.query.filter_by(email=email).first()
        if type == "registration":
            return user_record.registration_challenge
        elif type == "authentication":
            return user_record.authentication_challenge
        else:
            raise InvalidChallengeType
