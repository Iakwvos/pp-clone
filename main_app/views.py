import hashlib
import json
import os
import re
import time
import logging
from io import BytesIO

import requests
from bs4 import BeautifulSoup
from PIL import Image
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.conf import settings
from django.urls import reverse
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from gotrue import errors as gotrue_errors
from gotrue.errors import AuthRetryableError, AuthApiError

from supabase import create_client, Client
import openai
import shopify

# ---------------------
# Logging Configuration
# ---------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed logs

# Create handlers
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

file_handler = logging.FileHandler(os.path.join(settings.BASE_DIR, 'app.log'))
file_handler.setLevel(logging.ERROR)  # Log errors to file

# Create formatters and add to handlers
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

PLAN_LIMITS = {
    'Free': {
        'max_products': 3,
        'max_stores': 1,
        'price': 0,
        'generations_per_month': 3,
        'features': [
            'Access to basic features',
            'Community support',
            'Limited to 3 products',
            '1 connected store',
            'Basic analytics',
            'Standard security',
            'Limited promotional offers',
            'Basic product listing capabilities',
            'Access to community forums',
            'User guide for getting started',
        ],
    },
    'Starter': {
        'max_products': 20,
        'max_stores': 3,
        'price': 29,
        'generations_per_month': 20,
        'features': [
            'Access to all basic features',
            'Email support',
            'Up to 20 products',
            '3 connected stores',
            'Standard analytics',
            'Advanced security',
            'Customizable templates',
            'Promotional discounts for upgrades',
            'Integration with social media channels',
            'Monthly performance reports',
        ],
    },
    'Professional': {
        'max_products': 100,
        'max_stores': 10,
        'price': 99,
        'generations_per_month': 100,
        'features': [
            'All features included',
            'Priority support',
            'Unlimited products',
            'Up to 10 connected stores',
            'Advanced analytics',
            'Premium security',
            'Early access to new features',
            'Personalized onboarding',
            'Dedicated account manager',
            'Access to exclusive webinars and training sessions',
        ],
    },
}




# ---------------------
# Initialize Clients
# ---------------------
supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
openai.api_key = settings.OPENAI_API_KEY

# ---------------------
# Helper Functions
# ---------------------


def sanitize_title(title):
    sanitized = re.sub(r'[^A-Za-z0-9]+', '_', title).strip('_')
    return sanitized


def get_user_id(request):
    """Retrieve the user_id from the session."""
    return request.session.get('user_id')


def handle_exception(request, e, user_id, context):
    """
    Log the exception and provide user feedback.

    Args:
        request (HttpRequest): The HTTP request object.
        e (Exception): The exception that was raised.
        user_id (str): The ID of the user involved in the error.
        context (str): Additional context about where the error occurred.

    Returns:
        None
    """
    logger.error("Error in %s for user_id %s: %s", context, user_id, e)
    messages.error(
        request,
        f"An unexpected error occurred during {context.replace('_', ' ')}. Please try again."
    )


def signup_user(email, password):
    """Sign up a new user with Supabase."""
    try:
        response = supabase.auth.sign_up({'email': email, 'password': password})
        logger.debug("Signup response for %s: %s", email, response)
        return response
    except AuthRetryableError as e:
        logger.warning("Retryable error during signup for %s: %s", email, e)
        raise
    except AuthApiError as e:
        logger.error("API error during signup for %s: %s", email, e)
        raise
    except Exception as e:
        logger.error("Unexpected error during signup for %s: %s", email, e)
        raise


def login_user(email, password):
    """Log in a user with Supabase."""
    try:
        response = supabase.auth.sign_in_with_password(
            {'email': email, 'password': password}
        )
        logger.debug("Login response for %s: %s", email, response)
        return response
    except AuthApiError as e:
        logger.error("API error during login for %s: %s", email, e)
        raise
    except Exception as e:
        logger.error("Unexpected error during login for %s: %s", email, e)
        raise


def reset_password(email):
    """Initiate password reset for a user."""
    try:
        response = supabase.auth.reset_password_for_email(email)
        logger.debug("Password reset response for %s: %s", email, response)
        return response
    except AuthApiError as e:
        logger.error("API error during password reset for %s: %s", email, e)
        raise
    except Exception as e:
        logger.error("Unexpected error during password reset for %s: %s", email, e)
        raise


def initialize_shopify_session(shop_url, api_version, private_app_password):
    """Initialize the Shopify session and show the store's name."""
    try:
        shopify.ShopifyResource.clear_session()
        session = shopify.Session(shop_url, api_version, private_app_password)
        shopify.ShopifyResource.activate_session(session)
    except shopify.errors.ShopifyError as e:
        logger.error("Shopify error initializing session for %s: %s", shop_url, e)
        raise
    except Exception as e:
        logger.error("Unexpected error initializing Shopify session for %s: %s", shop_url, e)
        raise


def parse_ai_response(request, response_text, selected_images):
    """Parse AI response and integrate selected images."""
    try:
        parsed_data = {
            'title': '',
            'descriptions': [],
            'key_benefits': [],
            'reviews': [],
            'hooks': [],
            'full_names': [],
            'images': selected_images[:5],  # Limit to 5 images
            'json_template': ''
        }

        lines = response_text.split('\n')
        current_section = None

        for line in lines:
            line = line.strip()
            if line.startswith('_Title:'):
                current_section = 'title'
                parsed_data['title'] = line[len('_Title:'):].strip()
            elif line.startswith('_Descriptions:'):
                current_section = 'descriptions'
                descriptions = line[len('_Descriptions:'):].strip().rstrip('|').split(' | ')
                parsed_data['descriptions'] = descriptions
            elif line.startswith('_Key Benefits:'):
                current_section = 'key_benefits'
                benefits = line[len('_Key Benefits:'):].strip().rstrip('|').split(' | ')
                parsed_data['key_benefits'] = benefits
            elif line.startswith('_Reviews:'):
                current_section = 'reviews'
                reviews = line[len('_Reviews:'):].strip().rstrip('|').split(' | ')
                parsed_data['reviews'] = reviews
            elif line.startswith('_Hooks:'):
                current_section = 'hooks'
                hooks = line[len('_Hooks:'):].strip().rstrip('|').split(' | ')
                parsed_data['hooks'] = hooks
            elif line.startswith('_Full Names:'):
                current_section = 'full_names'
                names = line[len('_Full Names:'):].strip().rstrip('|').split(' | ')
                parsed_data['full_names'] = names
            elif line.startswith('_Image Links:'):
                continue
            else:
                if current_section and current_section in parsed_data:
                    parsed_data[current_section].append(line.rstrip('|').strip())

        logger.debug("AI response parsed successfully.")
        return parsed_data
    except Exception as e:
        logger.error("Error parsing AI response: %s", e)
        messages.error(
            request,
            "Failed to parse the AI-generated description. Please try again."
        )
        raise


def create_replacements(parsed_data):
    """Create placeholder replacements for the Shopify template."""
    replacements = {}

    for key, value in parsed_data.items():
        if isinstance(value, list):
            for idx, item in enumerate(value):
                placeholder = f"{{data['{key}'][{idx}]}}"
                replacements[placeholder] = item
        else:
            placeholder = f"{{data['{key}']}}"
            replacements[placeholder] = value

    return replacements


def upload_images_and_get_handles(request, image_urls):
    """
    Upload multiple images to Shopify via a temporary product and return their handles.

    Args:
        request (HttpRequest): The HTTP request object.
        image_urls (list): List of image URLs to upload.

    Returns:
        list: List of Shopify image handles.
    """
    handles = []
    shop_url = "https://2cce04-3a.myshopify.com/"
    api_version = '2024-07'
    private_app_password = "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"
    temp_product_title = "Temp Product for Image Upload (DO NOT TOUCH)"

    try:
        initialize_shopify_session(shop_url, api_version, private_app_password)

        # Check if the temporary product already exists
        existing_products = shopify.Product.find(title=temp_product_title)
        if existing_products:
            temp_product = existing_products[0]
            logger.info("Using existing temporary product with ID: %s", temp_product.id)
        else:
            # Create a new temporary product if it doesn't exist
            temp_product = shopify.Product()
            temp_product.title = temp_product_title
            temp_product.body_html = "This product is used temporarily for image uploads."
            temp_product.vendor = "Temporary Vendor"
            temp_product.product_type = "Temporary Type"
            if temp_product.save():
                logger.info("Temporary product created with ID: %s", temp_product.id)
            else:
                logger.error("Failed to create temporary product. Errors: %s", temp_product.errors.full_messages())
                return handles

        # Upload images to the temporary product
        for image_url in image_urls:
            try:
                if not image_url.startswith(('http://', 'https://')):
                    image_url = 'https:' + image_url
                response = requests.head(image_url, allow_redirects=True, timeout=5)
                if response.status_code != 200:
                    logger.warning("Invalid image URL or unreachable resource: %s", image_url)
                    continue
                image = shopify.Image()
                image.product_id = temp_product.id
                image.src = image_url
                if image.save():
                    formatted_handle = extract_image_handle(image.src)
                    handles.append(formatted_handle)
                    logger.info("Image uploaded successfully: %s", image_url)
                else:
                    logger.error("Failed to upload image: %s, Errors: %s", image_url, image.errors.full_messages())
            except requests.RequestException as e:
                logger.warning("Request error while validating URL %s: %s", image_url, e)
            except Exception as e:
                logger.error("Error uploading image %s: %s", image_url, e)

    except shopify.errors.ShopifyError as e:
        logger.error("Shopify error during image upload process: %s", e)
    except Exception as e:
        logger.error("Unexpected error during image upload process: %s", e)
    finally:
        shopify.ShopifyResource.clear_session()
    return handles


def extract_image_handle(image_src):
    """
    Extract the image handle from the image source URL.

    Args:
        image_src (str): The source URL of the image.

    Returns:
        str: The handle of the image.
    """
    try:
        # Shopify image handles are typically the filename without the extension
        handle = os.path.splitext(os.path.basename(image_src))[0]
        return handle
    except Exception as e:
        logger.error("Error extracting handle from image src %s: %s", image_src, e)
        return ""


def create_replacements(product_data):
    """
    Creates a dictionary mapping placeholders in the Shopify template to actual product data.

    Args:
        product_data (dict): The product data from Supabase.

    Returns:
        dict: A dictionary where keys are placeholders and values are actual data.
    """
    replacements = {}

    # Title
    replacements["{data['title']}"] = product_data.get('title', '')

    # Descriptions
    for idx, description in enumerate(product_data.get('descriptions', [])):
        placeholder = f"{{data['descriptions'][{idx}]}}"
        replacements[placeholder] = description

    # Key Benefits
    for idx, benefit in enumerate(product_data.get('key_benefits', [])):
        placeholder = f"{{data['key benefits'][{idx}]}}"
        replacements[placeholder] = benefit

    # Reviews
    for idx, review in enumerate(product_data.get('reviews', [])):
        placeholder = f"{{data['reviews'][{idx}]}}"
        replacements[placeholder] = review

    # Hooks
    for idx, hook in enumerate(product_data.get('hooks', [])):
        placeholder = f"{{data['hooks'][{idx}]}}"
        replacements[placeholder] = hook

    # Full Names
    for idx, name in enumerate(product_data.get('full_names', [])):
        placeholder = f"{{data['full names'][{idx}]}}"
        replacements[placeholder] = name

    return replacements


# ---------------------
# Helper Decorators
# ---------------------


def login_required(view_func):
    """Decorator to ensure the user is logged in."""
    def wrapper(request, *args, **kwargs):
        user_id = get_user_id(request)
        if not user_id:
            logger.warning("Unauthorized access attempt to %s", request.path)
            messages.error(request, "You must be logged in to access this page.")
            return redirect('main_page')
        return view_func(request, *args, **kwargs)
    return wrapper


def log_view(func):
    """Decorator to log entry and exit of view functions."""
    def wrapper(request, *args, **kwargs):
        logger.debug("Entering %s", func.__name__)
        response = func(request, *args, **kwargs)
        logger.debug("Exiting %s", func.__name__)
        return response
    return wrapper


# ---------------------
# View Functions
# ---------------------


@log_view
def main_page(request):
    """Render the main landing page."""
    return render(request, 'main_page.html')


@log_view
def signup_view(request):
    """Handle user registration."""
    # If user is already authenticated, redirect to dashboard
    if get_user_id(request):
        return redirect('dashboard')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        logger.info("Signup attempt for email: %s", email)

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                response = signup_user(email, password)
                if response.error:
                    messages.error(request, response.error.message)
                    logger.warning("Signup error for %s: %s", email, response.error.message)
                    return redirect('signup')

                # Initialize profile with generations left based on plan
                plan = 'Free'
                generations_left = PLAN_LIMITS[plan]['generations_per_month']
                supabase.table('profiles').insert({
                    'user_id': response.user.id,
                    'plan': plan,
                    'generations_left': generations_left,
                    'products_generated': 0,
                }).execute()

                messages.success(request, 'Signup successful. Please check your email to verify your account.')
                logger.info("Signup successful for %s", email)
                return redirect('login')
            except AuthRetryableError as e:
                logger.warning("AuthRetryableError on attempt %d for signup: %s", attempt, e)
                if attempt < max_retries:
                    time.sleep(2)  # Wait before retrying
                    continue
                messages.error(request, "The sign-up operation timed out. Please try again later.")
                return redirect('signup')
            except AuthApiError as e:
                messages.error(request, e.message)
                logger.error("AuthApiError during signup for %s: %s", email, e)
                return redirect('signup')
            except Exception as e:
                messages.error(request, "An unexpected error occurred during signup.")
                logger.error("Unexpected error during signup for %s: %s", email, e)
                return redirect('signup')

    return render(request, 'signup.html')


@log_view
def login_view(request):
    """Manage user authentication."""
    # If user is already authenticated, redirect to dashboard
    if get_user_id(request):
        return redirect('dashboard')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        logger.info("Login attempt for email: %s", email)

        try:
            response = login_user(email, password)
            if response and response.user:
                user_id = response.user.id
                request.session['user_id'] = user_id
                messages.success(request, "Login successful!")
                logger.info("User %s logged in successfully.", email)
                return redirect('dashboard')
            else:
                if response.error:
                    error_message = response.error.message
                    if "Invalid login credentials" in error_message:
                        messages.error(request, "Incorrect password. Please try again.")
                        logger.warning("Incorrect password for %s", email)
                    elif "User not found" in error_message:
                        messages.error(request, "No account found with this email. Please sign up.")
                        logger.warning("User not found during login for %s", email)
                    else:
                        messages.error(request, error_message)
                        logger.warning("Login error for %s: %s", email, error_message)
                return redirect('login')
        except AuthApiError as e:
            messages.error(request, "Invalid login credentials. Please try again.")
            logger.warning("AuthApiError during login for %s: %s", email, e)
            return redirect('login')
        except Exception as e:
            messages.error(request, "An unexpected error occurred during login.")
            logger.error("Unexpected error during login for %s: %s", email, e)
            return redirect('login')

    return render(request, 'login.html')

    


@log_view
def password_reset_view(request):
    """Facilitate the password reset process."""
    if request.method == 'POST':
        email = request.POST.get('email')
        logger.info("Password reset attempt for email: %s", email)
        try:
            response = reset_password(email)
            if response.error:
                messages.error(request, response.error.message)
                logger.warning("Password reset error for %s: %s", email, response.error.message)
            else:
                messages.success(request, 'Password reset email sent.')
                logger.info("Password reset email sent to %s", email)
        except AuthApiError as e:
            messages.error(request, e.message)
            logger.error("AuthApiError during password reset for %s: %s", email, e)
        except Exception as e:
            messages.error(request, "An unexpected error occurred during password reset.")
            logger.error("Unexpected error during password reset for %s: %s", email, e)
        return redirect('login')
    return render(request, 'password_reset.html')


@log_view
@login_required
def logout_view(request):
    """Log out the current user."""
    user_id = get_user_id(request)
    if user_id:
        logger.info("User ID %s logged out.", user_id)
    request.session.flush()
    messages.success(request, 'You have been logged out.')
    return redirect('main_page')


@log_view
@login_required
def dashboard_view(request):
    """Display the user's dashboard with dynamic stats."""
    user_id = get_user_id(request)
    connected_stores = []  # Initialize to avoid UnboundLocalError
    try:
        # Fetch user's products
        products_response = supabase.table('products').select('*').eq('user_id', user_id).execute()
        products = products_response.data if products_response.data else []
        products_generated = len(products)

        # Fetch user's profile
        profile_response = supabase.table('profiles').select('*').eq('user_id', user_id).single().execute()
        profile = profile_response.data or {}
        logger.debug("Fetched profile for user_id %s", user_id)

        full_name = profile.get('full_name', 'User')
        plan = profile.get('plan', 'Free')
        generations_left = profile.get('generations_left', PLAN_LIMITS[plan]['generations_per_month'])

        # Get plan limits
        plan_limits = PLAN_LIMITS.get(plan, PLAN_LIMITS['Free'])
        max_products = plan_limits['max_products']
        max_stores = plan_limits['max_stores']

        # Fetch connected stores with details
        stores_response = supabase.table('stores').select('*').eq('user_id', user_id).execute()
        connected_stores = stores_response.data if stores_response.data else []
        stores_connected = len(connected_stores)

        # Calculate generations left
        generations_left = max(0, generations_left - products_generated)

    except Exception as e:
        handle_exception(request, e, user_id, "dashboard_view")
        products = []
        profile = {}
        full_name = 'User'
        plan = 'Free'
        max_products = PLAN_LIMITS['Free']['max_products']
        max_stores = PLAN_LIMITS['Free']['max_stores']
        products_generated = 0
        generations_left = PLAN_LIMITS['Free']['generations_per_month']
        stores_connected = 0
        connected_stores = []  # Ensure it's defined in case of an exception

    return render(request, 'dashboard.html', {
        'products': products,
        'profile': profile,
        'full_name': full_name,
        'plan': plan,
        'products_generated': products_generated,
        'generations_left': generations_left,
        'stores_connected': stores_connected,
        'max_products': max_products,
        'max_stores': max_stores,
        'connected_stores': connected_stores,  # Pass connected_stores to the template
    })





@log_view
@login_required
def product_detail_view(request, product_id):
    """Show detailed information about a specific product."""
    user_id = get_user_id(request)
    try:
        # Fetch the product from Supabase
        product_response = supabase.table('products').select('*').eq('id', product_id).single().execute()
        product = product_response.data

        if not product:
            messages.error(request, 'Product not found.')
            logger.warning("Product ID %s not found for user_id %s", product_id, user_id)
            return redirect('dashboard')

        # Check ownership
        if product['user_id'] != user_id:
            messages.error(request, 'You are not authorized to view this product.')
            logger.warning("Unauthorized access to product ID %s by user_id %s", product_id, user_id)
            return redirect('dashboard')

        logger.debug("Displaying details for product ID %s by user_id %s", product_id, user_id)
        return render(request, 'product_detail.html', {'product': product})
    except Exception as e:
        handle_exception(request, e, user_id, "product_detail_view")
        return redirect('dashboard')


@log_view
@login_required
def edit_store_view(request, store_id):
    user_id = get_user_id(request)
    try:
        # Fetch the store
        store_response = supabase.table('stores').select('*').eq('id', store_id).single().execute()
        store = store_response.data

        if not store or store['user_id'] != user_id:
            messages.error(request, 'You are not authorized to edit this store.')
            return redirect('dashboard')

        if request.method == 'POST':
            # Update store details
            shop_url = request.POST.get('shop_url')
            shopify_api_key = request.POST.get('shopify_api_key')
            shopify_api_secret = request.POST.get('shopify_api_secret')
            store_name = request.POST.get('name')

            supabase.table('stores').update({
                'shop_url': shop_url,
                'shopify_api_key': shopify_api_key,
                'shopify_api_secret': shopify_api_secret,
                'name': store_name,
            }).eq('id', store_id).execute()

            messages.success(request, 'Store updated successfully.')
            return redirect('dashboard')
        else:
            # Render the edit store form
            return render(request, 'edit_store.html', {'store': store})
    except Exception as e:
        handle_exception(request, e, user_id, "edit_store_view")
        return redirect('dashboard')


@log_view
@login_required
def delete_store_view(request, store_id):
    user_id = get_user_id(request)
    if request.method == 'POST':
        try:
            # Verify store ownership
            store_response = supabase.table('stores').select('user_id').eq('id', store_id).single().execute()
            store = store_response.data

            if not store or store['user_id'] != user_id:
                messages.error(request, 'You are not authorized to delete this store.')
                return redirect('dashboard')

            # Delete the store
            supabase.table('stores').delete().eq('id', store_id).execute()
            messages.success(request, 'Store deleted successfully.')
        except Exception as e:
            handle_exception(request, e, user_id, "delete_store_view")
    return redirect('dashboard')

@log_view
@login_required
def connect_store_view(request):
    user_id = get_user_id(request)
    if request.method == 'POST':
        shop_url = request.POST.get('shop_url')
        shopify_api_key = request.POST.get('shopify_api_key')
        shopify_api_secret = request.POST.get('shopify_api_secret')
        store_name = request.POST.get('name')

        try:
            supabase.table('stores').insert({
                'user_id': user_id,
                'shop_url': shop_url,
                'shopify_api_key': shopify_api_key,
                'shopify_api_secret': shopify_api_secret,
                'name': store_name,
            }).execute()

            messages.success(request, 'Store connected successfully.')
            return redirect('dashboard')
        except Exception as e:
            handle_exception(request, e, user_id, "connect_store_view")
            return redirect('connect_store')
    else:
        return render(request, 'connect_store.html')


@log_view
@login_required
def delete_product_view(request, product_id):
    """Allow users to delete a specific product."""
    user_id = get_user_id(request)
    if request.method == 'POST':
        try:
            # Verify product ownership
            product_response = supabase.table('products').select('user_id').eq('id', product_id).single().execute()
            product = product_response.data

            if not product or product['user_id'] != user_id:
                messages.error(request, 'You are not authorized to delete this product.')
                logger.warning("Unauthorized delete attempt for product ID %s by user_id %s", product_id, user_id)
                return redirect('dashboard')

            # Delete the product
            supabase.table('products').delete().eq('id', product_id).execute()
            messages.success(request, 'Product deleted successfully.')
            logger.info("Product ID %s deleted by user_id %s", product_id, user_id)
        except Exception as e:
            handle_exception(request, e, user_id, "delete_product_view")
    return redirect('dashboard')


@log_view
@login_required
def generate_product_view(request):
    """Handles the initial form submission from the dashboard."""
    user_id = get_user_id(request)
    if request.method == 'POST':
        # Fetch user's plan and products generated
        try:
            profile_response = supabase.table('profiles').select('plan', 'generations_left').eq('user_id', user_id).single().execute()
            profile = profile_response.data or {}
            plan = profile.get('plan', 'Free')
            generations_left = profile.get('generations_left', 0)

            if generations_left <= 0:
                messages.error(request, f"You have reached your product generation limit for the {plan} plan. Please upgrade to continue.")
                logger.warning("User ID %s has reached product generation limit.", user_id)
                return redirect('upgrade_plan')  # Redirect to upgrade plan page
        except Exception as e:
            handle_exception(request, e, user_id, "generate_product_view")
            return redirect('dashboard')

        # Proceed with product generation
        product_url = request.POST.get('product_url')
        language = request.POST.get('language')
        category = request.POST.get('category')
        description = request.POST.get('description')

        if not product_url or not language or not category or not description:
            messages.error(request, 'All fields are required to generate a product.')
            logger.warning("Missing fields in product generation by user_id %s", user_id)
            return redirect('dashboard')

        # Validate product_url
        validator = URLValidator()
        try:
            validator(product_url)
        except ValidationError:
            messages.error(request, 'Enter a valid Product URL.')
            logger.warning("Invalid product_url provided: %s by user_id %s", product_url, user_id)
            return redirect('dashboard')

        # Store in session
        request.session['product_generation'] = {
            'product_url': product_url,
            'language': language,
            'category': category,
            'description': description,
        }
        logger.debug("Stored product_generation session data for user_id %s", user_id)

        # Render image selection step immediately
        return render(request, 'generate_product_step2.html', {
            'title': 'Fetching Images...',  # Placeholder, will be updated via AJAX
            'language': language,
            'category': category,
            'description': description,
        })

    # If GET request, redirect to dashboard
    return redirect('dashboard')



@log_view
@login_required
def fetch_images_view(request):
    """
    Handles AJAX requests to fetch images from the product URL.
    Returns a JSON response with images and product title.
    """
    user_id = get_user_id(request)
    product_generation = request.session.get('product_generation')
    logger.info("Fetching images for user_id %s", user_id)

    if not product_generation:
        logger.warning("No product_generation data found in session for user_id %s", user_id)
        return JsonResponse({'error': 'No product generation data found.'}, status=400)

    product_url = product_generation.get('product_url')
    language = product_generation.get('language')

    if not product_url or not language:
        logger.warning("Missing product_url or language in session for user_id %s", user_id)
        return JsonResponse({'error': 'Product URL and language are required.'}, status=400)

    # Validate product_url
    validator = URLValidator()
    try:
        validator(product_url)
    except ValidationError:
        logger.warning("Invalid product_url provided in session: %s for user_id %s", product_url, user_id)
        return JsonResponse({'error': 'Invalid product URL provided.'}, status=400)

    # Fetch and process images
    try:
        response = requests.get(product_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        title_tag = soup.find('h1')
        title = title_tag.text.strip() if title_tag else "Product Title"
        logger.debug("Extracted title: %s for user_id %s", title, user_id)

        images = []
        image_tags = soup.find_all('img')
        for img in image_tags:
            img_src = img.get('src')
            if not img_src:
                continue
            if not img_src.startswith(('http://', 'https://')):
                img_src = 'https:' + img_src
            if img_src.startswith('http'):
                try:
                    img_response = requests.get(img_src, stream=True, timeout=5)
                    img_response.raise_for_status()
                    img_data = img_response.content
                    image_file = BytesIO(img_data)
                    with Image.open(image_file) as image:
                        width, height = image.size
                        images.append({
                            'src': img_src,
                            'width': width,
                            'height': height
                        })
                except Exception as e:
                    logger.warning("Failed to process image %s: %s", img_src, e)
                    continue  # Skip images that cannot be processed

        if not images:
            logger.warning("No valid images found on the product page: %s for user_id %s", product_url, user_id)
            return JsonResponse({'error': 'No valid images found on the product page.'}, status=400)

        # Sort images by area (largest first) and limit
        images.sort(key=lambda x: x['width'] * x['height'], reverse=True)
        MAX_IMAGES = 100
        images = images[:MAX_IMAGES]
        logger.debug("Fetched and sorted %d images for user_id %s", len(images), user_id)

        # Update session with title and images
        request.session['product_generation']['title'] = title
        request.session['product_generation']['images'] = images
        logger.debug("Updated session with title and images for user_id %s", user_id)

        # Return the images and title
        return JsonResponse({
            'title': title,
            'language': language,
            'images': images
        })
    except requests.exceptions.RequestException as e:
        logger.error(
            "RequestException while fetching images from %s for user_id %s: %s",
            product_url,
            user_id,
            e
        )
        return JsonResponse({'error': f"Error fetching product data: {str(e)}"}, status=500)
    except Exception as e:
        logger.error("Unexpected error in fetch_images_view for user_id %s: %s", user_id, e)
        return JsonResponse({'error': f"An unexpected error occurred: {str(e)}"}, status=500)


@log_view
@login_required
def review_product_view(request):
    """
    Handles the submission of selected images.
    Generates the AI structured summary and renders the review page (step 3).
    """
    if request.method == 'POST':
        selected_images = request.POST.getlist('selected_images')
        title = request.POST.get('title')
        language = request.POST.get('language')
        user_id = get_user_id(request)
        logger.info("Review product submission by user_id %s", user_id)

        if not selected_images:
            messages.error(request, 'Please select at least one image.')
            logger.warning("No images selected in review_product_view by user_id %s", user_id)
            return redirect('generate_product')

        product_generation = request.session.get('product_generation')
        if not product_generation:
            messages.error(request, 'Product generation data not found.')
            logger.warning("No product_generation data in session for user_id %s", user_id)
            return redirect('dashboard')

        product_url = product_generation.get('product_url')
        try:
            response = requests.get(product_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            text_content = soup.get_text(separator='\n', strip=True)
            logger.debug("Fetched text content from %s for user_id %s", product_url, user_id)
        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error fetching product data: {str(e)}")
            logger.error("Error fetching product data from %s for user_id %s: %s", product_url, user_id, e)
            return redirect('dashboard')

        # Upload selected images to Shopify and get their handles
        image_urls = selected_images
        try:
            image_handles = upload_images_and_get_handles(request, image_urls)
            if not image_handles:
                messages.error(request, "Failed to upload images to Shopify.")
                logger.error("Failed to upload images for user_id %s", user_id)
                return redirect('dashboard')
            logger.info("Uploaded images and obtained handles for user_id %s", user_id)
        except Exception as e:
            messages.error(request, "An error occurred while uploading images to Shopify.")
            logger.error("Error uploading images for user_id %s: %s", user_id, e)
            return redirect('dashboard')

        # Prepare the analysis prompt
        analysis_prompt = (
            "Analyze the following HTML content and provide a structured summary strictly following the output format specified below. "
            "The output must be in **English** and must use a **playful but premium tone**, incorporating plenty of emojis (avoiding the rainbow emoji). "
            "**All output must strictly adhere to the format and language guidelines provided.** "
            "Do not include any numbering or additional text outside of the exact format. Ensure that each section and its content are separated by ' | ' exactly as shown.\n\n"
            "Sections to include in the summary:\n\n"
            "1. Title: A single line title.\n\n"
            "2. Descriptions: Five different descriptions with the specified character limits:\n"
            "   - 1st Description: 220-250 characters\n"
            "   - 2nd Description: 750-800 characters\n"
            "   - 3rd Description: 750-800 characters\n"
            "   - 4th Description: 750-800 characters\n"
            "   - 5th Description: 750-800 characters\n\n"
            "3. Key Benefits: Three different key benefits, each within 15-30 characters.\n\n"
            "4. Reviews: Five different reviews, formatted exactly as specified:\n"
            "   - 1st Review: 270-300 characters\n"
            "   - 2nd Review: 220-250 characters\n"
            "   - 3rd Review: 220-250 characters\n"
            "   - 4th Review: 220-250 characters\n"
            "   - 5th Review: 220-250 characters\n\n"
            "5. Hooks: Five different hooks, formatted exactly as specified:\n"
            "   - 1st Hook: 35-50 characters\n"
            "   - 2nd Hook: 35-50 characters\n"
            "   - 3rd Hook: 35-50 characters\n"
            "   - 4th Hook: 330-350 characters (must mention refund guarantee)\n"
            "   - 5th Hook: 380-400 characters (must focus on customer satisfaction)\n\n"
            "6. Image Links: Five different image links.\n\n"
            "7. Random Full Names: Five different random full names.\n\n"
            "Output Format:\n"
            "_Title: [Your Title Here]\n"
            "_Descriptions: [1st Description] | [2nd Description] | [3rd Description] | [4th Description] | [5th Description] |\n"
            "_Key Benefits: [1st Key Benefit] | [2nd Key Benefit] | [3rd Key Benefit] |\n"
            "_Reviews: [1st Review] | [2nd Review] | [3rd Review] | [4th Review] | [5th Review] |\n"
            "_Hooks: [1st Hook] | [2nd Hook] | [3rd Hook] | [4th Hook] | [5th Hook] |\n"
            "_Image Links: [1st Image Link] | [2nd Image Link] | [3rd Image Link] | [4th Image Link] | [5th Image Link] |\n"
            "_Full Names: [1st Full Name] | [2nd Full Name] | [3rd Full Name] | [4th Full Name] | [5th Full Name] |\n\n"
            f"HTML Content:\n{text_content}\n"
        )

        # Send the prompt to the AI model and get the response
        try:
            completion = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": analysis_prompt}]
            )
            response_text = completion.choices[0].message.content
            logger.debug("AI response received for user_id %s", user_id)
        except openai.error.OpenAIError as e:
            logger.error("OpenAI error generating AI description for user_id %s: %s", user_id, e)
            messages.error(
                request,
                "Failed to generate AI description. Please try again later."
            )
            return redirect('dashboard')
        except Exception as e:
            logger.error("Unexpected error generating AI description for user_id %s: %s", user_id, e)
            messages.error(
                request,
                "An unexpected error occurred while generating the AI description."
            )
            return redirect('dashboard')

        # Parse the AI's response
        try:
            parsed_data = parse_ai_response(request, response_text, selected_images)
            logger.debug("Parsed AI response for user_id %s", user_id)

            # Load the Shopify JSON template
            template_path = os.path.join(settings.BASE_DIR, 'product.shopify_template.json')
            try:
                with open(template_path, 'r', encoding='utf-8') as file:
                    shopify_template = json.load(file)  # Load as JSON directly
                logger.debug("Shopify template loaded successfully for user_id %s", user_id)
            except UnicodeDecodeError as e:
                messages.error(request, "Error reading Shopify template file.")
                logger.error("UnicodeDecodeError reading Shopify template for user_id %s: %s", user_id, e)
                return redirect('dashboard')
            except FileNotFoundError as e:
                messages.error(request, "Shopify template file not found.")
                logger.error("FileNotFoundError reading Shopify template for user_id %s: %s", user_id, e)
                return redirect('dashboard')
            except json.JSONDecodeError as e:
                messages.error(request, "Error parsing Shopify template file.")
                logger.error("JSONDecodeError reading Shopify template for user_id %s: %s", user_id, e)
                return redirect('dashboard')
            except Exception as e:
                messages.error(request, "Unexpected error reading Shopify template.")
                logger.error("Unexpected error reading Shopify template for user_id %s: %s", user_id, e)
                return redirect('dashboard')

            # Replace placeholders in the template with parsed_data
            formatted_json = shopify_template
            replacements = create_replacements(parsed_data)

            for placeholder, actual_value in replacements.items():
                actual_value = actual_value.replace('\\', '\\\\').replace('"', '\\"')
                formatted_json = json.loads(json.dumps(formatted_json).replace(placeholder, actual_value))

            parsed_data['json_template'] = formatted_json
            logger.debug("Formatted JSON template for user_id %s", user_id)

            # Store parsed data in session for later use
            request.session['product_generation']['parsed_data'] = parsed_data
            logger.debug("Stored parsed_data in session for user_id %s", user_id)

            # Render the review page with parsed data and the image handles
            return render(request, 'generate_product_step3.html', {
                'title': parsed_data.get('title'),
                'language': language,
                'images': parsed_data.get('images', []),
                'descriptions': parsed_data.get('descriptions', []),
                'key_benefits': parsed_data.get('key_benefits', []),
                'reviews': parsed_data.get('reviews', []),
                'hooks': parsed_data.get('hooks', []),
                'full_names': parsed_data.get('full_names', []),
                'image_handles': image_handles
            })
        except Exception as e:
            logger.error("Error parsing AI response for user_id %s: %s", user_id, e)
            messages.error(
                request,
                "Failed to process the AI-generated description. Please try again."
            )
            return redirect('dashboard')

    return redirect('dashboard')




@log_view
@login_required
def save_product_view(request):
    """Handles the final submission from the review page to save the product."""
    if request.method == 'POST':
        title = request.POST.get('title')
        language = request.POST.get('language')
        product_data = request.POST.get('product_data')  # Existing field
        user_id = get_user_id(request)
        logger.info("Save product submission by user_id %s", user_id)

        if not product_data:
            messages.error(request, 'No product data provided.')
            logger.warning("No product_data in save_product_view by user_id %s", user_id)
            return redirect('dashboard')

        try:
            # Parse the product_data JSON
            product_data_parsed = json.loads(product_data)
            logger.debug("Parsed product_data for product '%s' by user_id %s", title, user_id)
        except json.JSONDecodeError as e:
            messages.error(request, 'Invalid JSON format in product data.')
            logger.error("JSONDecodeError for product '%s' by user_id %s: %s", title, user_id, e)
            return redirect('dashboard')

        # Get image URLs and handles from POST data
        image_urls = request.POST.getlist('image_urls')
        image_handles = request.POST.getlist('image_handles')

        if not image_urls or not image_handles or len(image_urls) != len(image_handles):
            messages.error(request, 'Image URLs and handles are missing or mismatched.')
            logger.warning("Image URLs and handles missing or mismatched for user_id %s", user_id)
            return redirect('dashboard')

        # Combine image URLs and handles into a list of dictionaries
        images = [{'url': url, 'handle': handle} for url, handle in zip(image_urls, image_handles)]

        # Validate required fields in product_data
        required_fields = ['title', 'descriptions', 'key_benefits', 'reviews', 'hooks', 'full_names']
        missing_fields = [field for field in required_fields if field not in product_data_parsed or not product_data_parsed[field]]
        if missing_fields:
            messages.error(request, f"Missing fields in product data: {', '.join(missing_fields)}.")
            logger.warning("Missing fields in product_data for user_id %s: %s", user_id, missing_fields)
            return redirect('dashboard')

        # Prepare the product_data JSON for saving
        product_data_final = {
            'title': product_data_parsed.get('title'),
            'descriptions': product_data_parsed.get('descriptions'),
            'key_benefits': product_data_parsed.get('key_benefits'),
            'reviews': product_data_parsed.get('reviews'),
            'hooks': product_data_parsed.get('hooks'),
            'full_names': product_data_parsed.get('full_names'),
            'images': images,
            'created_at': 'now()'  # Store both URLs and handles
        }

        # Save the product
        try:
            supabase.table('products').insert({
                'user_id': user_id,
                'title': title,
                'description': None,  # Existing column
                'language': language,
                'images': image_urls,  # Existing field: storing only URLs
                'image_handles': image_handles,  # New field: storing handles
                'product_data': product_data_final,
                'is_imported': False,  # Initially set to false
                'created_at': 'now()'  # New JSON column
            }).execute()

            # Update generations_left and products_generated in the profile
            profile_response = supabase.table('profiles').select('*').eq('user_id', user_id).single().execute()
            profile = profile_response.data or {}
            generations_left = profile.get('generations_left', 0) - 1
            products_generated = profile.get('products_generated', 0) + 1
            supabase.table('profiles').update({
                'generations_left': generations_left,
                'products_generated': products_generated,
            }).eq('user_id', user_id).execute()

            messages.success(request, 'Product page created successfully.')
            logger.info("Product '%s' saved successfully for user_id %s", title, user_id)

            # Clear session data
            if 'product_generation' in request.session:
                del request.session['product_generation']
                logger.debug("Cleared product_generation session for user_id %s", user_id)

            return redirect('dashboard')
        except Exception as e:
            handle_exception(request, e, user_id, "save_product_view")
            return redirect('dashboard')

    # If GET request, redirect to dashboard
    return redirect('dashboard')



@log_view
@login_required
def upgrade_plan_view(request):
    """Handle plan upgrades."""
    user_id = get_user_id(request)

    try:
        # Fetch user's current profile
        profile_response = supabase.table('profiles').select('*').eq('user_id', user_id).single().execute()
        profile = profile_response.data or {}
        current_plan = profile.get('plan', 'Free')
    except Exception as e:
        handle_exception(request, e, user_id, "upgrade_plan_view")
        current_plan = 'Free'

    if request.method == 'POST':
        new_plan = request.POST.get('plan')
        # Validate new_plan
        if new_plan not in PLAN_LIMITS.keys():
            messages.error(request, "Invalid plan selected.")
            logger.warning("Invalid plan selection: %s by user_id %s", new_plan, user_id)
            return redirect('upgrade_plan')

        # Prevent downgrading to a lower plan
        plan_hierarchy = {'Free': 1, 'Starter': 2, 'Professional': 3}
        if plan_hierarchy.get(new_plan, 0) <= plan_hierarchy.get(current_plan, 0):
            messages.error(request, "You can only upgrade to a higher plan.")
            logger.warning("User_id %s attempted to downgrade from %s to %s", user_id, current_plan, new_plan)
            return redirect('upgrade_plan')

        # Update user's plan and reset generations_left
        try:
            generations_left = PLAN_LIMITS[new_plan]['generations_per_month']
            supabase.table('profiles').update({
                'plan': new_plan,
                'generations_left': generations_left,
            }).eq('user_id', user_id).execute()
            messages.success(request, f"Your plan has been upgraded to {new_plan}.")
            logger.info("User ID %s upgraded to plan %s.", user_id, new_plan)
            return redirect('dashboard')
        except Exception as e:
            handle_exception(request, e, user_id, "upgrade_plan_view")
            messages.error(request, "Failed to upgrade plan. Please try again later.")
            return redirect('upgrade_plan')
    else:
        # GET request - render the upgrade plan page
        return render(request, 'upgrade_plan.html', {
            'current_plan': current_plan,
            'plan_limits': PLAN_LIMITS,  # Pass plan limits to the template
        })



@log_view
@login_required
def shopify_auth_view(request):
    """Initiate Shopify authentication."""
    shop = request.GET.get('shop')
    user_id = get_user_id(request)
    logger.info("Shopify auth initiation by user_id %s for shop %s", user_id, shop)

    if not shop:
        messages.error(request, 'Shop parameter is missing.')
        logger.warning("Missing shop parameter in shopify_auth_view for user_id %s", user_id)
        return redirect('dashboard')

    api_key = settings.SHOPIFY_API_KEY
    scopes = ['write_products']
    redirect_uri = request.build_absolute_uri(reverse('shopify_callback'))

    try:
        shopify.Session.setup(api_key=api_key, secret=settings.SHOPIFY_API_SECRET)
        session = shopify.Session(shop, api_version='2021-04')
        permission_url = session.create_permission_url(scopes, redirect_uri)
        logger.debug("Permission URL created for Shopify auth: %s", permission_url)
        return redirect(permission_url)
    except shopify.errors.ShopifyError as e:
        messages.error(request, "Error initiating Shopify authentication.")
        logger.error("ShopifyError initiating Shopify auth for user_id %s: %s", user_id, e)
        return redirect('dashboard')
    except Exception as e:
        messages.error(request, "An unexpected error occurred during Shopify authentication.")
        logger.error("Unexpected error initiating Shopify auth for user_id %s: %s", user_id, e)
        return redirect('dashboard')


@log_view
@login_required
def shopify_callback_view(request):
    """Handle Shopify authentication callback."""
    params = request.GET.dict()
    shop = params.get('shop')
    user_id = get_user_id(request)
    logger.info("Shopify callback received for shop %s by user_id %s", shop, user_id)

    if not shop:
        messages.error(request, 'Shop parameter is missing.')
        logger.warning("Missing shop parameter in shopify_callback_view for user_id %s", user_id)
        return redirect('dashboard')

    api_key = settings.SHOPIFY_API_KEY
    api_secret = settings.SHOPIFY_API_SECRET

    try:
        shopify.Session.setup(api_key=api_key, secret=api_secret)
        session = shopify.Session(shop, api_version='2021-04')
        access_token = session.request_token(params)
        logger.debug("Obtained Shopify access token for shop %s by user_id %s", shop, user_id)
    except shopify.errors.ShopifyError as e:
        messages.error(request, "Error obtaining Shopify access token.")
        logger.error("ShopifyError obtaining access token for shop %s by user_id %s: %s", shop, user_id, e)
        return redirect('dashboard')
    except Exception as e:
        messages.error(request, "An unexpected error occurred while obtaining Shopify access token.")
        logger.error("Unexpected error obtaining Shopify access token for shop %s by user_id %s: %s", shop, user_id, e)
        return redirect('dashboard')

    # Save access_token and shop URL to session
    request.session['shopify_access_token'] = access_token
    request.session['shop_url'] = shop
    logger.info("Shopify account connected successfully for shop %s by user_id %s", shop, user_id)

    messages.success(request, 'Shopify account connected successfully.')
    return redirect('dashboard')


def create_theme_asset(asset_key, asset_content, theme_id):
    """
    Create and upload an asset to the specified Shopify theme.

    Args:
        asset_key (str): The key/path for the asset in Shopify.
        asset_content (str): The content of the asset.
        theme_id (int): ID of the Shopify theme.

    Returns:
        bool: True if asset creation is successful, False otherwise.
    """
    try:
        asset = shopify.Asset()
        asset.key = asset_key  # e.g., "templates/product_sanitizedtitle.json"
        asset.value = asset_content  # Assign content directly
        asset.content_type = 'application/json'  # Set correct content type for JSON

        # Calculate the MD5 checksum
        checksum = hashlib.md5(asset.value.encode('utf-8')).hexdigest()
        asset.checksum = checksum
        asset.theme_id = theme_id  # Set theme ID

        # Save the asset
        if asset.save():
            logger.info("Asset '%s' created successfully.", asset.key)
            return True
        else:
            logger.error("Failed to create asset '%s'. Errors: %s", asset.key, asset.errors.full_messages())
            return False
    except Exception as e:
        logger.error("Error creating asset '%s': %s", asset_key, e)
        return False


@log_view
@login_required
@require_POST
def import_to_shopify_view(request):
    """Imports a product into Shopify using the product's description from the database."""
    user_id = get_user_id(request)
    is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest'

    if not user_id:
        if is_ajax:
            return JsonResponse({'success': False, 'error': 'Unauthorized access.'}, status=401)
        else:
            return redirect('login')

    # Extract data from POST request
    product_id = request.POST.get('product_id')
    selected_store_id = request.POST.get('selected_store')

    if not product_id or not selected_store_id:
        error_message = 'Product ID and Store ID are required.'
        logger.warning("Missing product_id or selected_store_id for user_id %s", user_id)
        if is_ajax:
            return JsonResponse({'success': False, 'error': error_message}, status=400)
        else:
            messages.error(request, error_message)
            return redirect('dashboard')

    try:
        # Fetch product data from Supabase
        product_response = supabase.table('products').select('*').eq('id', product_id).single().execute()
        product = product_response.data

        if not product:
            error_message = 'Product not found.'
            logger.warning("Product ID %s not found for user_id %s", product_id, user_id)
            if is_ajax:
                return JsonResponse({'success': False, 'error': error_message}, status=404)
            else:
                messages.error(request, error_message)
                return redirect('dashboard')

        # Verify store ownership
        store_response = supabase.table('stores').select('*').eq('id', selected_store_id).single().execute()
        store = store_response.data

        if not store or store['user_id'] != user_id:
            error_message = 'You are not authorized to use this store.'
            logger.warning("Unauthorized store access: store_id %s by user_id %s", selected_store_id, user_id)
            if is_ajax:
                return JsonResponse({'success': False, 'error': error_message}, status=403)
            else:
                messages.error(request, error_message)
                return redirect('dashboard')

        # Proceed with importing to Shopify
        import_success = perform_shopify_import(product, store)

        if import_success:
            # Update product status to 'imported' in Supabase
            supabase.table('products').update({
                'is_imported': True,
            }).eq('id', product_id).execute()

            success_message = 'Product imported to Shopify successfully.'
            logger.info("Product ID %s imported successfully to store_id %s by user_id %s", product_id, selected_store_id, user_id)
            if is_ajax:
                return JsonResponse({
                    'success': True,
                    'message': success_message,
                    'redirect_url': reverse('dashboard')  # Correctly retrieve the URL
                }, status=200)
            else:
                messages.success(request, success_message)
                return redirect('dashboard')
        else:
            error_message = 'Failed to import product to Shopify.'
            logger.error("Failed to import product ID %s to store_id %s by user_id %s", product_id, selected_store_id, user_id)
            if is_ajax:
                return JsonResponse({'success': False, 'error': error_message}, status=500)
            else:
                messages.error(request, error_message)
                return redirect('dashboard')

    except Exception as e:
        handle_exception(request, e, user_id, "import_to_shopify_view")
        error_message = 'An unexpected error occurred during import.'
        logger.exception("Exception during import_to_shopify_view for user_id %s: %s", user_id, str(e))
        if is_ajax:
            return JsonResponse({'success': False, 'error': error_message}, status=500)
        else:
            messages.error(request, error_message)
            return redirect('dashboard')





def perform_shopify_import(product, store):
    """
    Handles the logic for importing a product into Shopify.
    This includes initializing the Shopify session, creating theme assets,
    replacing placeholders, and creating the product.
    Returns a tuple (success: bool, message: str).
    """
    try:
        # Initialize Shopify session
        initialize_shopify_session(store['shop_url'], '2024-07', store['shopify_api_secret'])

        # Fetch current Shopify store and theme
        shop = shopify.Shop.current()
        logger.debug("Connected to Shopify store: %s", shop.name)

        # Get the first available theme
        themes = shopify.Theme.find()
        if not themes:
            message = 'No Shopify themes found.'
            logger.warning(message)
            return False, message

        theme = themes[0]
        theme_id = theme.id
        logger.debug("Using Theme ID: %s", theme_id)

        # Sanitize the product title for the template name
        sanitized_title = sanitize_title(product['title'])
        template_filename = f"product.{sanitized_title}.json"
        asset_key = f"templates/{template_filename}"

        # Load the Shopify JSON template
        template_path = os.path.join(settings.BASE_DIR, 'product.shopify_template.json')
        try:
            with open(template_path, 'r', encoding='utf-8') as file:
                shopify_template = file.read()  # Read as string for placeholder replacement
            logger.debug("Shopify template loaded successfully.")
        except FileNotFoundError:
            message = "Shopify template file not found."
            logger.error(message)
            return False, message
        except Exception as e:
            message = "Error reading Shopify template file."
            logger.error(f"{message}: {e}")
            return False, message

        # Perform placeholder replacements
        try:
            # Create replacements dictionary
            replacements = create_replacements(product.get('product_data', {}))

            # Replace placeholders in the template with actual values
            formatted_json = shopify_template
            for placeholder, actual_value in replacements.items():
                # Escape backslashes and double quotes in the actual value
                actual_value_escaped = actual_value.replace('\\', '\\\\').replace('"', '\\"')
                # Replace the placeholder with the escaped actual value
                formatted_json = formatted_json.replace(placeholder, actual_value_escaped)

            logger.debug("Placeholders replaced successfully in Shopify template.")

            # Replace image URL placeholders with actual image URLs
            for idx, img in enumerate(product.get('image_handles', [])):
                image_placeholder = f"{{data['image_links'][{idx}]}}"
                formatted_json = formatted_json.replace(image_placeholder, img)
                logger.debug("Replaced image placeholder %s with URL %s", image_placeholder, img)

        except Exception as e:
            message = "Error processing Shopify template placeholders."
            logger.error(f"{message}: {e}")
            return False, message

        # Upload the customized Shopify template as an asset
        try:
            asset = shopify.Asset()
            asset.key = asset_key  # e.g., "templates/product_sanitizedtitle.json"
            asset.value = formatted_json  # Assign content directly
            asset.content_type = 'application/json'  # Set correct content type for JSON

            # Calculate the MD5 checksum
            checksum = hashlib.md5(asset.value.encode('utf-8')).hexdigest()
            asset.checksum = checksum
            asset.theme_id = theme_id  # Set theme ID
            
            # Save the asset
            if asset.save():
                logger.info("Asset '%s' created successfully.", asset.key)
            else:
                error_messages = asset.errors.full_messages()
                message = f"Failed to create asset '{asset.key}': {error_messages}"
                logger.error(message)
                return False, message
        except shopify.errors.ShopifyError as e:
            message = f"Shopify error while creating asset: {e}"
            logger.error(message)
            return False, message
        except Exception as e:
            message = f"Unexpected error while creating asset: {e}"
            logger.error(message)
            return False, message

        # Create the Shopify product
        try:
            new_product = shopify.Product()
            new_product.title = product['title']
            new_product.body_html = product.get('description', '')
            new_product.vendor = "Your Vendor Name"  # Replace with actual vendor if available
            new_product.product_type = "General"  # Replace with actual product type if available
            new_product.template_suffix = sanitized_title  # Use the sanitized title as template_suffix

            # Add images to the product if available
            if product.get('images'):
                new_product.images = [{'src': img_url} for img_url in product.get('images', [])]

            # Save the new product in Shopify
            if new_product.save():
                logger.info("Product '%s' imported successfully to Shopify.", new_product.title)
            else:
                error_messages = new_product.errors.full_messages()
                message = f"Failed to import product to Shopify: {error_messages}"
                logger.error(message)
                return False, message

        except shopify.errors.ShopifyError as e:
            message = f"Shopify error while creating product: {e}"
            logger.error(message)
            return False, message
        except Exception as e:
            message = f"Unexpected error while creating Shopify product: {e}"
            logger.error(message)
            return False, message
        finally:
            # Clear the Shopify session
            shopify.ShopifyResource.clear_session()

        # If all steps succeeded
        return True, "Product imported successfully."
    except Exception as e:
        logger.error("Error initializing Shopify session: %s", e)
        return False, "Error initializing Shopify session."




@log_view
@login_required
def settings_view(request):
    """Handle user settings, including Shopify credentials."""
    user_id = get_user_id(request)
    logger.info("Accessing settings_view for user_id %s", user_id)

    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        shop_url = request.POST.get('shop_url')
        shopify_api_secret = request.POST.get('shopify_api_secret')
        logger.debug(
            "Settings update attempt by user_id %s: full_name=%s, shop_url=%s",
            user_id,
            full_name,
            shop_url
        )

        # Prepare profile data
        profile_data = {
            'user_id': user_id,
            'full_name': full_name,
            'shop_url': shop_url,
            'shopify_api_key': "None",
            'shopify_api_secret': shopify_api_secret,
            'updated_at': 'now()',
        }

        try:
            # Upsert the profile (insert or update)
            supabase.table('profiles').upsert(profile_data).execute()
            messages.success(request, 'Profile updated successfully.')
            logger.info("Profile updated successfully for user_id %s", user_id)
            return redirect('dashboard')
        except Exception as e:
            handle_exception(request, e, user_id, "settings_view")
            return redirect('settings')
    else:
        # Fetch existing profile data
        try:
            profile_response = supabase.table('profiles').select('*').eq('user_id', user_id).limit(1).execute()
            profile = profile_response.data[0] if profile_response.data else {}
            logger.debug("Fetched profile for user_id %s", user_id)
        except Exception as e:
            handle_exception(request, e, user_id, "settings_view")
            profile = {}

        return render(request, 'settings.html', {
            'full_name': profile.get('full_name', ''),
            'shop_url': profile.get('shop_url', ''),
            'shopify_api_key': profile.get('shopify_api_key', ''),
            'shopify_api_secret': profile.get('shopify_api_secret', ''),
        })


# ---------------------
# Error Handling Views
# ---------------------


@log_view
def handler404(request, exception):
    """Custom handler for 404 errors."""
    logger.warning("404 error at %s", request.path)
    return render(request, '404.html', status=404)


@log_view
def handler500(request):
    """Custom handler for 500 errors."""
    logger.error("500 error at %s", request.path)
    return render(request, '500.html', status=500)
