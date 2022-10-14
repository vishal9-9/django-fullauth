from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from account.models import User
from account.utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input-type': 'password'},write_only=True)
    class Meta:
        model=User
        fields=['email','name','password','password2']
        extra_kwargs={
            'password':{'write_only':True}
        }

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password & confirm password doesn't match")
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email','password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','email','name']

class UserChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input-type': 'password'},write_only=True)
    password2 = serializers.CharField(style={'input-type': 'password'},write_only=True)
    class Meta:
        model=User
        fields=['password','password2']


    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password & confirm password doesn't match")
        user.set_password(password)
        user.save()
        return attrs

class PasswordResetEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user=user)
            link = "http://localhost:3000/api/user/reset/"+uid+"/"+token+"/"
            data = { 
                'subject': 'subject',
                'body':'body',
                'to_email': email
            }
            Util.send_email(data=data)
            return attrs
        else:
            raise serializers.ValidationError("You are not a registered user")

class UserPasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input-type': 'password'},write_only=True)
    password2 = serializers.CharField(style={'input-type': 'password'},write_only=True)
    class Meta:
        model=User
        fields=['password','password2']


    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password & confirm password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token=token):
                raise serializers.ValidationError("Invalid Token")
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token=token)
            raise serializers.ValidationError("Invalid Token")
