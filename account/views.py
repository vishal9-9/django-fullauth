import json
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

from account.serializers import (UserLoginSerializer, UserProfileSerializer, 
UserRegistrationSerializer, UserChangePasswordSerializer, PasswordResetEmailSerializer, UserPasswordResetSerializer)
from account.renderers import Renderers

# Create your views here.

class UserRegistrationView(APIView):
    renderer_classes=[Renderers]
    def post(self, request, format = None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"status": 201, "success_message": "User created successfully"},status=201)
        return Response({"status": 400, "success_message": serializer.errors},status=400)

class UserLoginView(APIView):
    renderer_classes=[Renderers]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email,password=password)
            if user is not None:
                token = RefreshToken.for_user(user=user)
                return Response({"status": 200, "success_message": {
                    "refresh": str(token),
                    "access_token": str(token.access_token)
                }},status=200)
            else:
                return Response({"status": 404, "error_message": "Invalid email or password"},status=404)

class UserProfileView(APIView):
    renderer_classes=[Renderers]
    permission_classes=[IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response({"status": 200, "success_message": serializer.data},status=200)

class UserChangePasswordView(APIView):
    renderer_classes=[Renderers]
    permission_classes=[IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({"status": 200, "success_message": "Password Changed Successfully"},status=200)
        return Response({"status": 400, "error_message": "Failed"},status=400)

class PasswordResetEmailView(APIView):
    renderer_classes=[Renderers]
    def post(self, request, format=None):
        serializer = PasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({"status": 200, "success_message": f'Email sent to {serializer.data["email"]}'},status=200)
        return Response({"status": 400, "error_message": serializer.errors},status=400)

class UserPasswordResetView(APIView):
    renderer_classes=[Renderers]
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({"status": 200, "success_message": "Password reset successful"},status=200)
        return Response({"status": 400, "error_message": serializer.errors},status=400)
