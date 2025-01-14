from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import GenreViewSet, BookViewSet, RentalViewSet, ReviewViewSet, RegisterView


router = DefaultRouter()
router.register(r'genres', GenreViewSet)
router.register(r'books', BookViewSet)
router.register(r'rentals', RentalViewSet)
router.register(r'reviews', ReviewViewSet)
    


urlpatterns = [
    path('', include(router.urls)),
    path('register/', RegisterView.as_view(), name='register'),
]
