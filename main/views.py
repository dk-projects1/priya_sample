from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.contrib.auth.hashers import make_password, check_password
from .models import User, Admin, Post
from django.urls import reverse
from bson import ObjectId
import random, smtplib
from base64 import b64encode
import requests

def is_username_available(username):
    try:
        User.objects.get(username=username)
        return False
    except User.DoesNotExist:
        return True
    
def is_email_available(email):
    try:
        User.objects.get(email=email)
        return False
    except User.DoesNotExist:
        return True

def is_post_available(title):
    try:
        Post.objects.get(title=title)
        return False
    except Post.DoesNotExist:
        return True    
    
def otp_verification(receiver_email):
        otp = str(random.randint(100000, 999999))

        sender_email = "devaprojects66@gmail.com"
        sender_password = "rcde xqjv tbuj tkcw"

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()

        server.login(sender_email, sender_password)

        subject = "Your OTP"
        body = f"Your OTP is: {otp}"
        message = f"Subject: {subject}\n\n{body}"

        server.sendmail(sender_email, receiver_email, message)

        server.quit()  
        return otp  

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        re_pass = request.POST['re_pass']

        if not is_username_available(username):
            error = "Username is already taken. Please choose a different username."
            return render(request, 'signup.html', {'error': error})
        
        if not is_email_available(email):
            error = "This mail ID is already registered."
            return render(request, 'signup.html', {'error': error})
               
        if password == re_pass:
            otp = otp_verification(email)
            request.session['name'] = username
            request.session['email'] = email
            request.session['password'] = password
            request.session['otp'] = otp
            return redirect(reverse('otp_verify'))
        else:
            error = "Password mismatch!"
            return render(request, 'signup.html', {'error': error})

    return render(request, 'signup.html')

def otp_verify(request):
    if request.method == 'POST':
        name =  request.session['name']
        email =  request.session.get('email')
        hashed_password = make_password(request.session['password'])
        otp = request.session['otp']
        e_otp = request.POST['otp']  

        if otp == e_otp:
            user = User(username=name, password=hashed_password, email=email) 
            user.save()
            return redirect('login')
        else:
            error = "Invalid OTP. Please try again."
            return render(request, 'otp_verification.html', {'email': email, 'error': error})

    return render(request, 'otp_verification.html')

def forgot_password(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST['password']
        re_pass = request.POST['re_pass']
        try:
            user = User.objects.get(username=username)
            otp = otp_verification(user.email)
            if password == re_pass:
                request.session['email'] = user.email
                request.session['password'] = password
                request.session['otp'] = otp
                return redirect(reverse('forgot_otp_verify'))
            else:
                error = "Password mismatch!"
            return render(request, 'forgot_password.html', {'error': error})
        except User.DoesNotExist:
            error = "User does not exist. Please sign up."
            return render(request, 'forgot_password.html', {'error': error})
    return render(request, 'forgot_password.html')  

def forgot_otp_verify(request):
    if request.method == 'POST':
        email =  request.session.get('email')
        hashed_password = make_password(request.session['password'])
        otp = request.session['otp']
        e_otp = request.POST['otp']  
        if otp == e_otp:
            try:
                user = User.objects.get(email=email)
                user.password = hashed_password
                user.save()
                return redirect('login')
            except User.DoesNotExist:
                error = "User does not exist. Please sign up."
                return render(request, 'otp_verification.html', {'email': email, 'error': error})
        else:
            error = "Invalid OTP. Please try again."
            return render(request, 'otp_verification.html', {'email': email, 'error': error})
    return render(request, 'otp_verification.html')

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        if username == "admin":
            admin = Admin.objects.get(username=username)
            if check_password(password, admin.password):
                request.session['admin_id'] = str(admin._id)
                return redirect('admin')
            else:
                error = "Invalid admin credentials. Please try again."
                return render(request, 'login.html', {'error': error})
        else:
            try:
                user = User.objects.get(username=username)
                if check_password(password, user.password):
                    request.session['user_id'] = str(user._id)
                    return redirect('home')
                else:
                    error = "Invalid credentials. Please try again."
                    return render(request, 'login.html', {'error': error})
            except User.DoesNotExist:
                error = "User does not exist. Please sign up."
                return render(request, 'login.html', {'error': error})

    if 'user_id' in request.session:
        return redirect('home')
    elif 'admin_id' in request.session:
        return redirect('admin')
    else:
        return render(request, 'login.html')

def logout(request):
    request.session.clear()
    return redirect('login')

def home(request):
    if 'user_id' in request.session:
        user_id = request.session['user_id']
        try:
            user = User.objects.get(pk=ObjectId(user_id))
            url = "https://drive.google.com/uc?export=view&id=" 
            all_posts = Post.objects.all()
            return render(request, 'home.html', {'name': user.username, 'email': user.email, 'all_posts': all_posts, 'url':url})
        except User.DoesNotExist:
            return redirect('login')
    else:
        return redirect('login')
    
def admin(request):
    if 'admin_id' in request.session:
        admin_id = request.session['admin_id']
        try:
            user = Admin.objects.get(pk=ObjectId(admin_id))
            url = "https://drive.google.com/uc?export=view&id="    
            all_posts = Post.objects.all() 
            for post in all_posts:
                print(post._id)
            if request.method == 'POST':
                title = request.POST['title']
                description = request.POST['Description']
                link = request.FILES.get('link')
                image = b64encode(link.read()).decode("utf-8")
                price = request.POST['price']
                if is_post_available(title):
                    post = Post(title=title, image=image, price = price, des = description)
                    post.save()
                    return redirect('admin')
                else:
                    error = "Show details are already posted"
                    return render(request, 'admin.html', {'error': error, 'all_posts': all_posts, 'url': url})      
            return render(request, 'admin.html', {'all_posts': all_posts, 'url': url, 'user': user})
        except Admin.DoesNotExist:
            return redirect('login')
    else:
        return redirect('login')

def edit_post(request, post_id):
    if 'admin_id' in request.session:
        admin_id = request.session['admin_id']
        post = get_object_or_404(Post, _id=post_id)

        if request.method == 'POST':
            title = request.POST['title']
            description = request.POST['Description']
            link = request.FILES.get('link')
            price = request.POST['price']
            if link is not None:
                post.title = title
                post.des = description
                post.image = b64encode(link.read()).decode("utf-8")
                post.price = price
                post.save() 
            else:   
                post.title = title
                post.price = price
                post.save()                

            return redirect('admin')
        else:
            return render(request, 'edit_post.html', {'post': post})
    else:
        return redirect('login')

def delete_post(request, post_id):
    if 'admin_id' in request.session:
        admin_id = request.session['admin_id']
        post = get_object_or_404(Post, _id=post_id)

        if request.method == 'POST':
            post.delete()
            return redirect('admin')
        else:
            return render(request, 'delete_post.html', {'post': post})
    else:
        return redirect('login')

def appoinments(request):
    if 'user_id' in request.session:
        if request.method == 'POST':
            accessToken = ""
            userId = ""
            name = request.POST.get('name', '')
            email = request.POST.get('email', '')
            num = request.POST.get('num', '')
            date = request.POST.get('date', '')
            time = request.POST.get('time', '')
            query = request.POST.get('message', '')
            message = f"Name: {name} \n Email: {email} \n Number: {num} \n Date: {date} \n Time: {time} \n Query: {query}"
            url = f"https://api.telegram.org/bot{accessToken}/sendMessage?chat_id={userId}&text={message}"
            print("url:", url)
            response = requests.post(url)
            if response.status_code == 200:
                return redirect('appoinments')
            else:
                return HttpResponse('<h1>Something went wrong! Please contact Shop to book the slot.</h1>')
        else:
            return render(request, 'contact.html')
    else:
        return redirect('login')   

def view_product(request, post_id):
    if 'user_id' in request.session:
        user_id = request.session['user_id']
        post = get_object_or_404(Post, _id=post_id)
        if request.method == 'POST':
            return redirect("appoinments")

        return render(request, "view_product.html", {"post":post})
    else:
        return redirect('login')
