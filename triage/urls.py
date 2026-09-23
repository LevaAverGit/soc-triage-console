from django.urls import path

from . import views

urlpatterns = [
    path("", views.IncidentListView.as_view(), name="incident-list"),
    path("incident/<str:incident_id>/", views.IncidentDetailView.as_view(), name="incident-detail"),
    path("incident/<str:incident_id>/status/", views.change_status, name="incident-status"),
    path("incident/<str:incident_id>/assign/", views.assign, name="incident-assign"),
    path("incident/<str:incident_id>/note/", views.add_note, name="incident-note"),
    path("incident/<str:incident_id>/attach/", views.upload_attachment, name="incident-attach"),
]
