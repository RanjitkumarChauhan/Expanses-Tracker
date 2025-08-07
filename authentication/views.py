from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.

def register_view(request):
    context = {
        'message':"This is register Page"
    }
    return HttpResponse(context["message"])

def login_view(request):
    context = {
        'message':"This is login Page"
    }
    return HttpResponse(context["message"])

