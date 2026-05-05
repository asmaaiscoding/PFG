from django.urls import path

from . import views

urlpatterns = [
    path("inbox/", views.inbox, name="inbox"),
    path("<int:pk>/", views.message_detail, name="message-detail"),
    path("send/", views.send_message, name="send-message"),
    path("<int:pk>/delete/", views.delete_message, name="delete-message"),
]
