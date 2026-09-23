from django.urls import path
from rest_framework.routers import DefaultRouter

from . import api

router = DefaultRouter()
router.register("incidents", api.IncidentViewSet, basename="incident")

urlpatterns = [
    path("metrics/", api.MetricsView.as_view(), name="api-metrics"),
    *router.urls,
]
