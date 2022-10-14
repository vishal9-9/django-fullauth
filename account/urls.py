from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from account.views import UserRegistrationView, UserLoginView, UserProfileView, UserChangePasswordView, PasswordResetEmailView, UserPasswordResetView

urlpatterns = [
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/user/register/', view=UserRegistrationView.as_view()),
    path('api/user/login/', view=UserLoginView.as_view()),
    path('api/user/', view=UserProfileView.as_view()),
    path('api/user/password/',view=UserChangePasswordView.as_view()),
    path('api/user/reset-password/',view=PasswordResetEmailView.as_view()),
    path('api/user/reset/<uid>/<token>/',view=UserPasswordResetView.as_view())
]
