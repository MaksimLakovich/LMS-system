from django_filters.rest_framework import DjangoFilterBackend

from rest_framework import generics, serializers
from rest_framework import status as drf_status
from rest_framework.views import APIView
from rest_framework.filters import OrderingFilter
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView

from users.models import CustomUser, Payments
from users.serializers import (
    CustomObtainPairSerializer,
    CustomUserSerializer,
    PaymentsSerializer,
)
from users.services import (
    create_stripe_price,
    create_stripe_product,
    create_stripe_session,
    get_stripe_payment_status,
)


class CustomUserListAPIView(generics.ListAPIView):
    """Класс-контроллер на основе базового Generic-класса для получения списка зарегистрированных пользователей.
    Доступно: аутентифицированным пользователям."""

    permission_classes = [IsAuthenticated]
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


class CustomUserCreateAPIView(generics.CreateAPIView):
    """Класс-контроллер на основе базового Generic-класса для регистрации пользователя.
    Доступно: всем пользователям."""

    permission_classes = [AllowAny]
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


class CustomUserRetrieveUpdateAPIView(generics.RetrieveUpdateAPIView):
    """Класс-контроллер на основе базового Generic-класса для получения и редактирования профиля пользователя.
    Доступно:
    1) Просматривать профиль пользователя может любой авторизованный пользователь (только без персональных данных).
    2) Редактировать профиль пользователя может только сам пользователь."""

    # Оптимизация работы - использование prefetch_related("payments"), что подтянет платежи одним SQL-запросом.
    # Это ускорит загрузку профиля, потому что платежи загрузятся за один SQL-запрос.
    queryset = CustomUser.objects.prefetch_related("payments").all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_context(self):
        """Передает request в сериализатор для дальнейшего анализа (например, в to_representation)."""
        context = super().get_serializer_context()
        context["request"] = self.request
        return context

    def check_object_permissions(self, request, obj):
        """Проверяет права доступа к редактированию профиля.
        Доступно:
        1) Просматривать (GET) может любой авторизованный пользователь.
        2) Редактировать (PUT, PATCH) может только владелец профиля.
        Если пользователь пытается изменить чужой профиль, то вызывается отказ в доступе (HTTP 403).
        """
        if request.method in ["PUT", "PATCH"] and request.user != obj:
            self.permission_denied(
                request, message="Можно редактировать только свой профиль."
            )
        return super().check_object_permissions(request, obj)


class CustomUserDestroyAPIView(generics.DestroyAPIView):
    """Класс-контроллер на основе базового Generic-класса для удаления пользователя."""

    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


class CustomTokenObtainPairView(TokenObtainPairView):
    """Класс-контроллер на основе TokenObtainPairView для авторизации по email."""

    permission_classes = [AllowAny]
    serializer_class = CustomObtainPairSerializer


class PaymentsListCreateAPIView(generics.ListCreateAPIView):
    """Класс-контроллер на основе базового Generic-класса для получения списка платежей и создания нового платежа:
        - GET: Возвращает список всех платежей пользователя.
        - POST: Создаёт платёж на продукт (Course или Lesson) и генерирует ссылку на оплату через Stripe.
    Важно:
    - Поля Stripe ("stripe_product_id", "stripe_price_id", "stripe_session_id", "payment_url") заполняются автоматом.
    - Пользователь подставляется из "request.user".
    """

    queryset = Payments.objects.all()
    serializer_class = PaymentsSerializer

    # Бэкенд для обработки фильтра:
    filter_backends = [
        DjangoFilterBackend,
        OrderingFilter,
    ]
    # Фильтрация по курсу, уроку и оплате:
    filterset_fields = (
        "paid_course",
        "paid_lesson",
        "payment_method",
    )
    # Сортировка по дате оплаты
    ordering_fields = ["payment_date"]

    def get_queryset(self):
        """Метод ограничивает список платежей только платежами текущего пользователя при выполнении GET-запроса."""
        return Payments.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Создание платежа с интеграцией к платёжной системе Stripe (если указан соответствующий payment_method).
        - Создаётся продукт в Stripe (по .title в объекте продукта);
        - Создаётся цена (в копейках);
        - Создаётся сессия оплаты и сохраняется "payment_url".
        - Все поля Stripe сохраняются в объект Payments."""
        user = self.request.user
        paid_course = serializer.validated_data.get("paid_course")
        paid_lesson = serializer.validated_data.get("paid_lesson")
        payment_amount = serializer.validated_data.get("payment_amount")
        payment_method = serializer.validated_data.get("payment_method")

        # 1) Stripe-интеграция нужна только если указан метод оплаты "=transfer"
        if payment_method == "transfer":

            # Интеграция со Stripe
            if paid_course:
                product_id = create_stripe_product(paid_course)
            elif paid_lesson:
                product_id = create_stripe_product(paid_lesson)
            else:
                raise serializers.ValidationError("Не указан оплачиваемый Курс или Урок.")

            price_id = create_stripe_price(product_id, payment_amount)
            session_id, session_url = create_stripe_session(price_id)

            # Сохранение результатов в БД
            serializer.save(
                user=user,
                stripe_product_id=product_id,
                stripe_price_id=price_id,
                stripe_session_id=session_id,
                payment_url=session_url,
            )

        # 2) Без интеграции со Stripe если указан метод оплаты "=cash"
        else:
            serializer.save(user=user)


class PaymentsRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    """Класс-контроллер на основе базового Generic-класса для получения, обновления и удаления одного платежа."""

    queryset = Payments.objects.all()
    serializer_class = PaymentsSerializer


class StripePaymentStatusAPIView(APIView):
    """Проверка статуса оплаты по session_id (или payment_id)."""

    def get(self, request, pk):
        """Возвращает статус платежа из Stripe."""
        try:
            payment = Payments.objects.get(pk=pk, user=request.user)
            if not payment.stripe_session_id:
                return Response({"detail": "Платёж не связан с Stripe-сессией."}, status=400)

            # Получаю статус из Stripe
            payment_status = get_stripe_payment_status(payment.stripe_session_id)

            # Обновляю в БД статус (опционально)
            payment.payment_status = payment_status
            payment.save(update_fields=["payment_status"])

            return Response({"payment_status": payment_status})

        except Payments.DoesNotExist:
            return Response({"detail": "Платёж не найден."}, status=404)

        except Exception as e:
            return Response({"detail": str(e)}, status=drf_status.HTTP_500_INTERNAL_SERVER_ERROR)
