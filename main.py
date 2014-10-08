#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import re
import os
import hashlib
import hmac
from string import letters
import random

from google.appengine.ext import db
from google.appengine.api import images


JINJA_ENVIRONMENT = jinja2.Environment(autoescape=True,
loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

secret="mylaptop"

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
PASS_RE = r'(/(?:[a-zA-Z0-9_ -.]+/?)*)'
usr = ['cool']
#signupusr = ""
#userlogin=["lan"]


def make_salt(length = 5):
        return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
        if not salt:
            salt = make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)



def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
        val = secure_val.split('|')[0]
        if secure_val == make_secure_val(val):
            return val



class FunctionHandler(webapp2.RequestHandler):
        def set_secure_cookie(self,val,username):
                cookie_val = make_secure_val(val)
                self.response.headers.add_header(
                        'Set-Cookie',
                        'name=%s; Path=/'%(cookie_val))
                
                self.response.headers.add_header(
                        'Set-Cookie',
                        'username=%s; Path=/'% str(username))


        def read_secure_cookie(self,name):
                cookie_val = self.request.cookies.get(name)
                #self.response.out.write(cookie_val)
                if cookie_val and check_secure_val(cookie_val):
                        return cookie_val


        
        def login(self, user):
                self.set_secure_cookie(str(user.key().id()),user.name)
                

        def logout(self):
                self.response.headers.add_header('Set-Cookie', 'name=; Path=/')
                self.response.headers.add_header('Set-Cookie', 'username=; Path=/')



class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    types = db.IntegerProperty(required = True)
    mobile = db.StringProperty(required = True)
    address = db.StringProperty(multiline = True)





class Signup(FunctionHandler):
    def write_form(self,user="",usererr="",passerr="",verifyerr="",againemail="",emailerr="",mobileerror="",addresserror=""):
        template_values = {"useragain":user,
                           "usererror":usererr,
                           "passerror":passerr,
                           "verifyerror":verifyerr,
                           "againemail":againemail,
                           "emailerror":emailerr,
                           "mobileerror":mobileerror,
                           "addresserror":addresserror
                        
                           }

        template = JINJA_ENVIRONMENT.get_template('form.html')
        self.response.out.write(template.render(template_values))

    
    def get(self):
        if self.read_secure_cookie('name'):
                self.redirect('/login')
        self.write_form()

    def post(self):

        usererr=""
        passerr=""
        verifyerr=""
        emailerr=""
        have_error=""
        email=""
        address=""
        mobile=""
        addresserror=""
        mobileerror=""
        
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PASSWORD_RE = re.compile(r"^.{3,20}$")
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        
        def valid_username(username):
            if USER_RE.match(username):
                return "valid"
            else:
                return


        def valid_password(password):
            if PASSWORD_RE.match(password):
                return "valid"
            else:
                return


        def valid_email(email):
            if EMAIL_RE.match(email):
                return "valid"
            else:
                return


        username=self.request.get('username')
        usr.pop(0)
        usr.append(username)
        #signupusr = ""
        global signupusr
        signupusr = username
        password=self.request.get('password')
        verify=self.request.get('verify')
        email=self.request.get('email')
        address=self.request.get('address')
        mobile=self.request.get('mobile')
        
        user_chk=valid_username(username)
        pass_chk=valid_password(password)
        email_chk=valid_email(email)

        #self.response.out.write(pass_chk)
        
        if not user_chk:
            #self.write_form("","please enter valid username","","","")
            usererr="enter a valid username"
            have_error=True

        if not pass_chk:
            passerr="enter a valid password"
            have_error=True
        elif password!=verify:
            verifyerr="your passwords didn't match"
            have_error=True

        if email:
            if not email_chk:
                emailerr="enter a valid email"
                have_error=True

        if not address:
                addresserror="enter address"
                have_error=True

        if not mobile:
                mobileerror="enter mobile number"
                have_error=True

        if mobile:
                if not mobile.isdigit():
                        mobileerror="enter valid mobile"
                        have_error=True

        if have_error==True:
            self.write_form(username,usererr,passerr,verifyerr,email,emailerr,mobileerror,addresserror)
        else:
            #username=self.request.get('username')
            #self.response.out.write(self.username)
            #self.response.out.write("hello")
            u = User.all().filter('name =',username).get()
            if u:
                usererr="user already exists"
                self.write_form(username,usererr,"","",email,"")
            else:
                pw_hash=make_pw_hash(username,password)
                u=User(name=username,pw_hash=pw_hash,email=email,types=0,mobile=mobile,address=address)
                u.put()
                self.login(u)
                #self.redirect('/signup/welcome')
                self.redirect('/')


"""class WelcomeHandler(FunctionHandler):
    def get(self):
        #username=self.request.get('username')
        #usr=userlist[0]
        value=self.read_secure_cookie('name')
        if value: 
                self.response.out.write("welcome!"+ signupusr)
        else:
                self.redirect('/signup')"""

                
        #self.response.out.write(usr)
        #self.response.headers['Content-Type']='text/plain'
        #visits=0
        #visit_cookie_str=""
        #visit_cookie_str = self.request.cookies.get('name')
        #self.response.out.write(visit_cookie_str)
       # if visit_cookie_str:
        #    cookie_val=check_secure_val(visit_cookie_str)
         #   if cookie_val:
          #      visits=int(cookie_val)

        #visits+=1

        #new_cookie_val=make_secure_val(str(visits))
        #self.response.out.write(new_cookie_val)   
        #visits=self.request.cookies.get('visits','0')
        # make sure visits is an int
        #if visits.isdigit():
         #   visits=int(visits)+1
        #else:
         #   visits=0
        #self.response.headers.add_header('Set-Cookie','name=%s'%new_cookie_val




class Login(FunctionHandler):
        def write(self,invaliderror=""):
                template_values={"invaliderror":invaliderror}

                template = JINJA_ENVIRONMENT.get_template('login.html')
                self.response.out.write(template.render(template_values))


        def get(self):
                val = self.read_secure_cookie('name')
                if val:
                        self.redirect('/login/welcome')
                self.write()


        def post(self):
                username=self.request.get('username')
                usr.pop(0)
                usr.append(username)
                #userlogin.pop(0)
                #userlogin.append(username)
                password=self.request.get('password')

                u=User.all().filter('name =',username).get()
                if u and valid_pw(username,password,u.pw_hash):
                        self.login(u)
                        #self.redirect('/login/welcome')
                        self.redirect('/')
                else:
                        invaliderror="Invalid Login"
                        self.write(invaliderror)


"""class WelcomeLogin(FunctionHandler):
        def get(self):
                user = ""
                user=usr[0]
                #self.response.out.write(usr)
                value=self.read_secure_cookie('name')
                if value: 
                        self.response.out.write("welcome!"+ user)
                else:
                        self.redirect('/login')"""


class Logout(FunctionHandler):
        def get(self):
                self.logout()
                #self.redirect('/signup')
                self.redirect('/')





#### CMS frontpage


JINJA_ENVIRONMENT = jinja2.Environment(autoescape=True,
loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))


class DataPost(db.Model):
    content = db.TextProperty(required=False)
    groupheading = db.StringProperty()
    topicheading = db.StringProperty()
    postby = db.StringProperty(required = False)
    postid = db.StringProperty(required = True)
    avatar = db.BlobProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_mod = db.DateTimeProperty(auto_now = True)

class Discussion(db.Model):
    postedby = db.StringProperty(required=True)
    comment = db.StringProperty(multiline=True)
    link = db.StringProperty()


class Feedback(db.Model):
    sentby = db.StringProperty(required=True)
    data = db.StringProperty(multiline=True)
    senttime = db.DateTimeProperty(auto_now_add=True)


class Feed(webapp2.RequestHandler):
        def get(self):
                username=self.request.cookies.get('username')
                if username:
                        template_values={
                                         'username':username
                                        }
                        template = JINJA_ENVIRONMENT.get_template('feedback.html')
                        self.response.out.write(template.render(template_values))
                else:
                        self.redirect('/login')

        def post(self):
                username= self.request.cookies.get('username')
                data=self.request.get('feed')
                a=Feedback(sentby=username,data=data)
                a.put()
                #self.response.out.write('hello')
                self.redirect('/')
                



        
class WikiPage(FunctionHandler):
        def get(self,newpostid):
                #self.response.out.write(newpostid)
                """a,b,c=newpostid.split('/')
                self.response.out.write(b)
                self.response.out.write(c)"""
                checkpost = db.GqlQuery("select * from DataPost where postid =:postid \
                                        order by created desc limit 1",postid = newpostid).get()
                self.response.out.write("""<br><br>""")
        
                if checkpost:
                        if self.read_secure_cookie('name'):
                                a = db.GqlQuery("select * from DataPost where postid =:postid \
                                            order by created desc limit 1",postid = newpostid).get()
                                username= self.request.cookies.get('username')
                                usercheck = db.GqlQuery("select * from DataPost where postby=:postby \
                                                and postid=:newpostid",postby=username,newpostid=newpostid).get()
                                
                                usertype = db.GqlQuery("select * from User where name =:name",name=username).get()
                                
                                if usercheck or (usertype.types==1):
                                        #self.response.out.write("hello user found")
                                        edit=True
                        
                                else:
                                        #self.response.out.write("hello user not found")
                                        edit=False
                                        delete=False
                          
                                login = False
                                logout = True
                                signup = False
                                
                                if usertype.types==1:
                                        delete=True
                                else:
                                        delete=False
                                pagelink = newpostid
                                usernm = usr[0]
        
                                if a:
                                        prevcontent = a.content
                                else:
                                        prevcontent = ""

                        else:
                                login = True
                                logout = False
                                edit = False
                                signup = True
                                delete=False
                                prevcontent = ""
                                pagelink = ""
                                usernm = ""
        
                        link=newpostid
                        res=db.GqlQuery("select * from DataPost")
                        a=[]
                        if link=='/':
                            self.response.out.write("""<a class="grp" href ="/creategroup">Create Group</a>""")
                            for i in res:
                                    if not i.groupheading in a and (i.groupheading != ""):
                                            a.append(i.groupheading)
                                            num=0
                                            groupheading=i.groupheading
                                            numberofposts=db.GqlQuery("select * from DataPost where groupheading \
                                                    =:groupheading",groupheading=groupheading)
                                            for x in numberofposts:
                                                    num+=1

                                            self.response.out.write("""<br>""")
                                            num=str(num)
                                            self.response.out.write("""<pre>""")
                                            self.response.out.write("                       ")
                                            self.response.out.write("""<span style="font-family:Comic Sans MS">""")
                                            self.response.out.write("""<a href="/groups/%s">"""%groupheading)
                                            self.response.out.write(groupheading+ " (" + (num) + ")" )
                                            self.response.out.write("""</a>""")
                                            self.response.out.write("""</span>""")
                                            self.response.out.write("""</pre>""")

                                        
                                        
                        template_values = {
                                           'login': login,
                                           'logout': logout,
                                           'edit': edit,
                                           'signup': signup,
                                           'pagelink': pagelink,
                                           'usernm': usernm,
                                           'link':link,
                                           'delete':delete,
                                           'q': prevcontent
                                          } 
                       
                        template = JINJA_ENVIRONMENT.get_template('wikifront.html')
                        self.response.out.write(template.render(template_values))


                        #self.response.out.write(str(checkpost.key().id()))
                        self.response.out.write("""<br><br><br>""")
                        content = checkpost.content
                        for i in content:
                                content = content.replace('\n','<br>')
                        self.response.out.write("""<br>""")
                        self.response.out.write("""<pre>""")
                        self.response.out.write("""<div style="color:green;margin-left:5cm;font-family:Verdana">""")
                        self.response.out.write(content)
                        self.response.out.write("""</div>""")
                        self.response.out.write("""</pre>""")
                        checkpost = db.GqlQuery("select * from DataPost where postid =:postid",postid = newpostid)
                        for i in checkpost:
                                if i.avatar:
                                        self.response.out.write("""<br><br><br><br>""")
                                        #self.response.out.write(str(checkpost.key().id()))
                                        #self.response.out.write("""<p align="centre">""")
                                        self.response.out.write('<img src="/img?img_id=%s" align="middle"></img>' % i.key())
                                        #self.response.out.write("""</div>""")
                        pagecomments = db.GqlQuery("select * from Discussion where link =:link",link = newpostid)
                        template_values={
                                         'pagecomments':pagecomments,
                                         'link':link,
                                         'delete':delete
                                        }
                        if newpostid!='/':
                                template = JINJA_ENVIRONMENT.get_template('discussion.html')
                                self.response.out.write(template.render(template_values))



                else:
                        #self.response.out.write("not found")
                        self.redirect('/_edit' + newpostid)



        def post(self,newpostid):
                  submitid=self.request.get('post')
                  if submitid:
                          username= self.request.cookies.get('username')
                          if not username:
                                  username="Anonymous"
                          comment=self.request.get("comment")
                          a=Discussion(postedby=username,comment = comment,link=newpostid)
                          a.put()
                          self.redirect('%s' %newpostid)
                  else:
                          a = db.GqlQuery("select * from DataPost where postid =:postid \
                                          ",postid = newpostid).get()
                          db.delete(a)
                          self.redirect('/')
                
                
                



class CreateGrp(webapp2.RequestHandler):
    def get(self):
             template = JINJA_ENVIRONMENT.get_template('creategroup.html')
             self.response.out.write(template.render())
            
        
    def post(self):
        groupname = self.request.get("groupname")
        #self.response.out.write(groupname)
        self.redirect('/groups'+'/'+(groupname))



class Groups(CreateGrp):
    def get(self,groupname):
             #self.response.out.write(groupname)
             a=groupname[1:]
             checktopic = db.GqlQuery("select * from DataPost where groupheading =:x",x = a)
             
             template_values={
                              "groupname":groupname,
                              "checktopic":checktopic
                             }
             template = JINJA_ENVIRONMENT.get_template('createpost.html')
             self.response.out.write(template.render(template_values))
             



class TopicName(CreateGrp):
    def get(self,groupname):
             template = JINJA_ENVIRONMENT.get_template('createtopic.html')
             self.response.out.write(template.render())
             #self.response.out.write(groupname)

    def post(self,groupname):
            topicname=self.request.get("topicname")
            a=groupname+'/'+topicname
            self.response.out.write(a)
            self.redirect(a)
                                




class Image(webapp2.RequestHandler):
    def get(self):
        greeting = db.get(self.request.get('img_id'))
       
        #self.response.out.write("""<div style margin-left:5cm>""")
        #self.response.out.write("""<p align="centre">""")
        if greeting.avatar:
            self.response.headers['Content-Type'] = 'image/png'
            self.response.out.write(greeting.avatar)
        else:
            self.response.out.write('No image')




class EditPage(FunctionHandler):
        def get(self,newpostid):
                if self.read_secure_cookie('name'):
                        a = db.GqlQuery("select * from DataPost where postid =:postid order by created desc limit 1",postid = newpostid).get()
                        login = False
                        logout = True
                        signup = False
                        pagelink = newpostid
                        usernm = usr[0]
        
                        if a:
                                prevcontent = a.content
                        else:
                                prevcontent = ""

                        
                
                        template_values = {
                                           'login': login,
                                           'logout': logout,
                                           'signup': signup,
                                           'pagelink': pagelink,
                                           'usernm': usernm,
                                           'q': prevcontent
                                          } 
                        
                        template = JINJA_ENVIRONMENT.get_template('editform.html')
                        self.response.out.write(template.render(template_values))
                        """self.response.out.write(newpostid)
                        a,b,c=newpostid.split('/')
                        self.response.out.write(b)
                        self.response.out.write(c)"""

                else:
                        self.redirect('/login')



        def post(self,newpostid):
                #self.response.out.write("hello123")
                pic=self.request.get("photo")
                #self.response.headers['Content-Type'] = 'image/png'
                #self.response.out.write(pic)
                if not pic:
                        pic=""
                else:
                        pic = images.resize(pic, 520, 420)

                pic=db.Blob(pic)
                
                con = self.request.get('q')
                #self.response.out.write(newpostid)
                username= self.request.cookies.get('username')
                if newpostid!='/':
                        b,groupheading,topicheading=newpostid.split('/')
                else:
                       groupheading=""
                       topicheading=""
                a = DataPost(content = con,groupheading=groupheading,topicheading=topicheading,\
                             postby=username,postid = newpostid,avatar=pic)
                delete_post=db.GqlQuery("select * from DataPost where postid =:postid ",postid \
                                        = newpostid).get()
                if delete_post:
                        db.delete(delete_post)
                
                a.put()
                self.redirect(newpostid)

                                       

   
app = webapp2.WSGIApplication([
     ('/signup', Signup),
     ('/login',Login),
     ('/logout',Logout),
     ('/feedback',Feed),
     ('/creategroup',CreateGrp),
     ('/groups'+PASS_RE,Groups),
     ('/createpost'+PASS_RE,TopicName),
     ('/img',Image),
     ('/_edit'+PASS_RE, EditPage),
     (PASS_RE, WikiPage)
], debug=True)
