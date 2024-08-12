from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password   # Django의 기본 패스워드 검증도구
from django.contrib.auth import authenticate
# Django의 기본 authenticate 함수로, 우리가 설정한 DefaultAuthBackend인 TokenAuth 방식으로 유저를 인증해줌

from rest_framework import serializers
from rest_framework.authtoken.models import Token           # 토큰 모델
from rest_framework.validators import UniqueValidator       # 이메일 중복 방지를 위한 검증도구

from .models import Profile


class RegisterSerializer(serializers.ModelSerializer):      # 회원가입 시리얼라이저
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())],      # 이메일 중복 검증
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],     # 비밀번호 검증
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password2', 'email')
    
    def validate(self, data):       # 비밀번호 일치 여부 확인
        if data['password'] != data['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return data
    
    def create(self, validated_data):
    # CREATE 요청에 대해 create 메소드를 오버라이딩, 유저를 생성하고 토큰을 생성하게 함
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
        )
        user.set_password(validated_data['password'])
        user.save()
        token = Token.objects.create(user=user)
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    # write_only 옵션을 통해 클라이언트->서버 방향의 역직렬화는 가능, 서버->클라이언트 방향의 직렬화는 불가능
    def validate(self, data):
        user = authenticate(**data)
        if user:
            token = Token.objects.get(user=user)
            return token
        raise serializers.ValidationError(
            {"error": "Unable to log in with provided credentials."}
        )

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ("nickname", "position", "subjects", "image")

