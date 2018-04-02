import base64
import hashlib
import json
import os
import re
import smtplib
import sys
import urllib
import datetime 

from django.template.context_processors import csrf
from django.core.validators import validate_email
from django.db.utils import IntegrityError
from django.http import *
from django.shortcuts import render_to_response
from django.utils.http import urlquote_plus
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login as auth_login
from rest_framework import status

#from django.contrib.auth.models import User



from multiprocessing import Pool

from controlcenter.utils import *
from runtime.db.manager import DataHubManager
from crawler.views import RegisterCrawlingUser

p = os.path.abspath(os.path.dirname(__file__))

import logging
logger = logging.getLogger("Account")
User = get_user_model()


kEmail = "SESSION_EMAIL"
kUsername = "SESSION_USERNAME"
kUserId = "SESSION_USERID_DC"


# for async calls
pool = Pool(processes=1)  

'''
LOGIN/REGISTER/RESET
'''

def is_valid_username (username):
  try:
    if len(username) >3 and re.match(r'\w+', username).group() == username:
      return True
  except:
    pass

  return False

def login_required (f):
  def wrap (request, *args, **kwargs):
      if kEmail not in request.session.keys():        
        redirect_url = urlquote_plus(request.get_full_path())        
        return HttpResponseRedirect("/account/login?redirect_url=%s" %(redirect_url))
      return f(request, *args, **kwargs)
  wrap.__doc__ = f.__doc__
  wrap.__name__ = f.__name__
  return wrap


def login_form (request, redirect_url='/', errors=[]):
    c = {'redirect_url':redirect_url, 'errors':errors, 'values':request.GET}
    c.update(csrf(request))
    return render_to_response('account/dc_layout_login.html', c)
#     return HttpResponseRedirect('/dashboard/#/page/signin.html')

def register_form (request, redirect_url='/', errors=[]):
  c = {'redirect_url':redirect_url, 'errors':errors, 'values':request.POST}
  c.update(csrf(request))
  return render_to_response('account/signup.html', c)


def login (request):
  jsonOutput = {'success' : False}
  retStatus = 0
  
  redirect_url = '/cc/dashboard'
  if('redirect_url' in request.GET.keys()):
    redirect_url = urllib.unquote_plus(request.GET['redirect_url'])

  if not redirect_url or redirect_url == '':
    redirect_url = '/'

  if request.method == "POST":
    errors = []
    login_email = ''

    if('redirect_url' in request.POST.keys()):
      redirect_url = urllib.unquote_plus(request.POST['redirect_url'])
    
    email = None 
    try:
        login_id = request.POST["login_id"].lower()
        login_password = request.POST["login_password"]
#         login_password = hashlib.sha1(request.POST["login_password"]).hexdigest()

        try : 
            validate_email(login_id.lower().strip())
            email = login_id.lower().strip()
        except:
            pass

        user = None
        if email:
            user = User.objects.get(email=email)
            user = authenticate(username=user.username, password=login_password)
        else:
            try:
                user = authenticate(username=login_id, password=login_password)
            except Exception as e:
                print e
        if user.is_active:
            auth_login(request, user)
        clear_session(request)

        if user is not None : 
            jsonOutput['success']       = True
            jsonOutput['token']         = user.auth_token.key
            jsonOutput['userid']        = user.id
            jsonOutput['username']      = user.username
            jsonOutput['email']         = user.email
            jsonOutput['message']       = "login (ajax) successfully"
            jsonOutput['lastlogin']     = datetime.datetime.strftime(datetime.datetime.utcnow(), "%a, %d-%b-%Y %H:%M:%S GMT")
            jsonOutput['expired']       = datetime.datetime.strftime(datetime.datetime.utcnow() + datetime.timedelta(seconds=3600), "%a, %d-%b-%Y %H:%M:%S GMT")
            jsonOutput['redirect_url']  = redirect_url + urllib.unquote_plus('?auth_user=%s' %(user.username))
            
            request.session[kEmail]     = user.email
            request.session[kUsername]  = user.username
            request.session[kUserId]  = user.id
#             login(request, user)
#             return HttpResponseRedirect(redirect_url)
        else :
            retStatus                   = 1
            jsonOutput['success']       = True
            jsonOutput['message']       = "User " + login_id + " does not exist"
    except User.DoesNotExist:
      try:
        if email:
          User.objects.get(email=login_id)
        else:
          User.objects.get(username=login_id)
        retStatus = 1 # Wrong password    
        jsonOutput['success'] = False                  
        errors.append(
          'Wrong password. Please try again.<br /><br />'
          '<a class="blue bold" href="/account/forgot">Click Here</a> '
          'to reset your password.')
        jsonOutput['message'] = errors[0]  
      except User.DoesNotExist:
        retStatus = 2 # User does not exist                    
        jsonOutput['success'] = False  
        errors.append(
          'Could not find any account associated with login_id: '
          '%s.<br /><br /><a class="blue bold" '
          'href="/account/register?redirect_url=%s">Click Here</a> '
          'to create an account.' %(login_id,
              urllib.quote_plus(redirect_url)))
        jsonOutput['message'] = errors[0]  
#       return login_form(
#           request, redirect_url = urllib.quote_plus(redirect_url),
#           errors = errors) 
    except Exception as e:
        logger.debug("Login issue. Error=" + str(e))
        retStatus = 3
        jsonOutput['success'] = False
        jsonOutput['message'] = 'Login failed.'  
        errors.append('Login failed.')
#       return login_form(
#           request, redirect_url = urllib.quote_plus(redirect_url),
#           errors = errors)          
    finally : 
#         if retStatus != 0 :
        response = HttpResponse(json.dumps(jsonOutput), content_type="application/json",
                                status=status.HTTP_400_BAD_REQUEST if retStatus != 0 else status.HTTP_200_OK)
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Credentials"] = True
        return response
#         else : 
#             return HttpResponseRedirect(redirect_url)
  else:
        try:
          if request.session[kUsername]:
            redirect_url = redirect_url + urllib.unquote_plus('?auth_user=%s' %(request.session[kUsername]))
            return HttpResponseRedirect(redirect_url)
          else:
            return login_form(request, urllib.quote_plus(redirect_url))
        except:
          return login_form(request, urllib.quote_plus(redirect_url))


def signup (request):
    redirect_url = '/cc/dashboard'
    if('redirect_url' in request.GET.keys()):
        redirect_url = urllib.unquote_plus(request.GET['redirect_url'])

    if request.method == "POST":
        errors = []
        email = ''
        try:
            error = False
            if('redirect_url' in request.POST.keys()):
                redirect_url = urllib.unquote_plus(request.POST['redirect_url'])
        
            username = request.POST["username"].lower()
            email = request.POST["email"].lower()
            password = request.POST["password"]
            
            if(validate_email(email.strip())):
                errors.append("Invalid Email.")
                error = True
            if(username and not is_valid_username(username)):
                errors.append("Invalid Username.")
                error = True
            if(password == ""):
                errors.append("Empty Password.")
                error = True

            # set email default username
            if not username:
                username = email
        
            try:
                user = User.objects.get(email=email)
                errors.append("Email already registered.")
                error = True
            except User.DoesNotExist:
                pass

            try:
                user = User.objects.get(username=username)
                errors.append("Username already taken.")
                error = True
            except User.DoesNotExist:
                pass

            if(error):
                return register_form(request, redirect_url = urllib.quote_plus(redirect_url), errors = errors)
            
            jsonOutput = {}
            jsonOutput = RegisterCrawlingUser({"username": username, "email": email, "password": password})
            
            if not jsonOutput['success']:
                return register_form(request, redirect_url = urllib.quote_plus(redirect_url), errors = errors)
            
            clear_session(request)
            request.session[kEmail] = email
            request.session[kUsername] = username
            request.session[kUserId] = jsonOutput["userid"]
        
            encrypted_email = encrypt_text(email)
        
            subject = "Welcome to datacell.io"
        
            msg_body = '''
            Dear %s,
        
            Thanks for registering to datacell.io. 
        
            Please click the link below to start using datacell.io:
        
            %s://%s/verify/%s
        
            ''' % (
                email,
                'https' if request.is_secure() else 'http',
                request.get_host(),          
                encrypted_email)
        
            pool.apply_async(send_email, [email, subject, msg_body])
 
            jsonOutput['lastlogin']     = datetime.datetime.strftime(datetime.datetime.utcnow(), "%a, %d-%b-%Y %H:%M:%S GMT")
            jsonOutput['expired']       = datetime.datetime.strftime(datetime.datetime.utcnow() + datetime.timedelta(seconds=3600), "%a, %d-%b-%Y %H:%M:%S GMT")
            jsonOutput['redirect_url']  = redirect_url + urllib.unquote_plus('?auth_user=%s' %(username))
       
            response = HttpResponse(json.dumps(jsonOutput), content_type="application/json",
                                    status=status.HTTP_400_BAD_REQUEST if not jsonOutput['success'] else status.HTTP_200_OK)
            response["Access-Control-Allow-Origin"] = "*"
            response["Access-Control-Allow-Credentials"] = True
            return response
        except IntegrityError:
            errors.append(
              'Account with the email address <a href="mailto:%s">%s</a> already exists.<br /> <br />Please <a class="blue bold" href="/login?login_email=%s">Sign In</a>.'
              % (email, email, urllib.quote_plus(email)))
            return register_form(request, redirect_url = urllib.quote_plus(redirect_url), errors = errors)
        except Exception, e:
            errors.append("Error %s." %(str(e)))
            return register_form(request, redirect_url = urllib.quote_plus(redirect_url), errors = errors)
    else:
        return register_form(request, redirect_url = urllib.quote_plus(redirect_url))


def clear_session (request):
  request.session.flush()
  if kEmail in request.session.keys():
    del request.session[kEmail]
  if kUsername in request.session.keys():
    del request.session[kUsername]


def logout (request):
  clear_session(request)
  c = {
    'msg_title': 'Thank you for using datacell.io!',
    'msg_body': 'Your have been logged out.<br /><br /><a href="/login">Click Here</a> to sign in again.'
  } 
  c.update(csrf(request))
#   return render_to_response('account/confirmation.html', c)
  return HttpResponseRedirect("/")  

def forgot (request):
  if request.method == "POST":
    errors = []
    try:
      user_email = request.POST["email"].lower()
      user = User.objects.get(email=user_email)

      encrypted_email = encrypt_text(user_email)

      subject = "datacell.io Password Reset"

      msg_body = '''
      Dear %s,

      Please click the link below to reset your datacell.io password:

      %s://%s/account/reset/%s

      ''' % (
          user.email,
          'https' if request.is_secure() else 'http',
          request.get_host(), 
          encrypted_email)

      pool.apply_async(send_email, [user_email, subject, msg_body])

      c = {
        'msg_title': 'datacell.io Reset Password',
        'msg_body': 'A link to reset your password has been sent to your email address.'
      } 
      c.update(csrf(request))

      return render_to_response('account/confirmation.html', c)

    except User.DoesNotExist:
      errors.append(
          "Invalid Email Address.")
    except Exception, e:
      errors.append(
          'Error: %s.'
          'Please try again or send an email to '
          '<a href="mailto:info@datacell.ca">info@datacell.ca</a>.' %(str(e)))
    
    c = {'errors': errors, 'values': request.POST} 
    c.update(csrf(request))
    return render_to_response('account/forgot.html', c)
  else:
    c = {'values': request.REQUEST} 
    c.update(csrf(request))
    return render_to_response('account/forgot.html', c)

def verify (request, encrypted_email):
  errors = []
  c = {'msg_title': 'datacell.io Account Verification'}
  try:
    user_email = decrypt_text(encrypted_email)
    user = User.objects.get(email=user_email)
    c.update({
        'msg_body': 'Thanks for verifying your email address!<br /> <br /><a href="/">Click Here</a> to start using datacell.io.'
    })
    clear_session(request)
    request.session[kEmail] = user.email
    request.session[kUsername] = user.username
  except:
    errors.append(
        'Wrong verify code in the URL. '
        'Please try again or send an email to '
        '<a href="mailto:info@datacell.ca">info@datacell.ca</a>')
  
  c.update({'errors': errors})
  c.update(csrf(request))
  return render_to_response('account/confirmation.html', c)


def reset (request, encrypted_email):
  errors = []
  error = False
  if request.method == "POST":
    try:
      user_email = request.POST["user_email"].lower()
      password = request.POST["new_password"]
      password2 = request.POST["new_password2"]

      if password == "":
        errors.append("Empty Password.")
        error = True

      if password2 != password:
        errors.append("Password and Confirm Password don't match.")
        error = True

      if not error:
        hashed_password = hashlib.sha1(password).hexdigest()
        user = User.objects.get(email=user_email)
        try:
          DataHubManager.create_user(username=user.username, password=hashed_password)
        except Exception, e:
          pass

        try:
          DataHubManager.change_password(username=user.username, password=hashed_password)
        except Exception, e:
          errors.append(str(e))
          error = True

      if error:
        c = {
          'user_email': user_email,
          'encrypted_email': encrypted_email,
          'errors': errors
        }
        c.update(csrf(request))
        return render_to_response('account/reset.html', c)

      else:
        hashed_password = hashlib.sha1(password).hexdigest()
        user = User.objects.get(email=user_email)
        user.password = hashed_password
        user.save()
        c = {
          'msg_title': 'datacell.io Reset Password',
          'msg_body': 'Your password has been changed successfully.<br /> <br />'
                      '<a href="/account/login" class="blue bold">Click Here</a>'
                      ' to sign in.'
        } 
        c.update(csrf(request))
        return render_to_response('account/confirmation.html', c)
    except:
      errors.append(
          'Some unknown error happened. '
          'Please try again or send an email to '
          '<a href="mailto:info@datacell.ca">info@datacell.ca</a>')
      c = {'errors': errors} 
      c.update(csrf(request))
      return render_to_response('account/reset.html', c)
  else:
    try:
      user_email = decrypt_text(encrypted_email)
      User.objects.get(email=user_email)
      c = {
          'user_email': user_email,
          'encrypted_email': encrypted_email
      }
      c.update(csrf(request))
      return render_to_response('account/reset.html', c)
    except:
      errors.append(
          'Wrong reset code in the URL. '
          'Please try again or send an email to '
          '<a href="mailto:info@datacell.ca">info@datacell.ca</a>')
    
    c = {'msg_title': 'datacell.io Reset Password', 'errors': errors} 
    c.update(csrf(request))
    return render_to_response('account/confirmation.html', c)

def get_login(request):
  login = None
  try:
    login = request.session[kUsername]
  except:
    pass

  return login

@login_required
def jdbc_password(request):
  login = request.session[kUsername]
  user = User.objects.get(username=login)
  return HttpResponse(user.password)
