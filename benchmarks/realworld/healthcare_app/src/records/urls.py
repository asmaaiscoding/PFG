from django.urls import path

from . import views

urlpatterns = [
    path("<int:pk>/", views.record_detail, name="record-detail"),
    path("<int:pk>/notes/", views.record_notes, name="record-notes"),
    path("<int:pk>/share/", views.share_record, name="share-record"),
    path("upload/", views.upload_record, name="upload-record"),
]
