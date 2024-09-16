import os
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.conf import settings
from django.urls import reverse
from gotrue import errors as gotrue_errors
import time
from gotrue.errors import AuthRetryableError
import requests
from bs4 import BeautifulSoup
from io import BytesIO
from PIL import Image
from django.shortcuts import render, redirect
from django.contrib import messages
# Supabase client
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
import requests
from bs4 import BeautifulSoup
from io import BytesIO
from PIL import Image
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse

# Import your Supabase client
from supabase import create_client, Client

# OpenAI for AI-powered content generation
import openai

# Shopify API
import shopify

# For web scraping
import requests
from bs4 import BeautifulSoup

# Initialize Supabase client
supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

# Set OpenAI API key
openai.api_key = settings.OPENAI_API_KEY

# ---------------------
# Helper Functions
# ---------------------

def signup_user(email, password):
    response = supabase.auth.sign_up({'email': email, 'password': password})
    return response

def login_user(email, password):
    response = supabase.auth.sign_in_with_password({'email': email, 'password': password})
    return response

def reset_password(email):
    response = supabase.auth.reset_password_for_email(email)
    return response

def generate_ai_description(title, language):
    analysis_prompt = f"Write a compelling product description for '{title}' in {language}."
    
    # Make the API call using OpenAI's new SDK structure
    completion = openai.chat.completions.create(
        model="gpt-4o-mini",  # or "gpt-3.5-turbo"
        messages=[
            {"role": "user", "content": analysis_prompt}
        ]
    )

    # Correct way to access the response content using attributes
    response_content = completion.choices[0].message.content.strip()

    # Optionally format the response

    # Get the token usage from the response
    tokens_used = completion.usage.total_tokens

    return response_content, tokens_used

def initialize_shopify_session(shop_url, api_version, private_app_password):
    """Initialize the Shopify session."""
    shopify.ShopifyResource.clear_session()
    session = shopify.Session(shop_url, api_version, private_app_password)
    shopify.ShopifyResource.activate_session(session)


# ---------------------
# View Functions
# ---------------------

def main_page(request):
    return render(request, 'main_page.html')

def signup_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = signup_user(email, password)
                if response.error:
                    messages.error(request, response.error.message)
                    return redirect('signup')
                messages.success(request, 'Signup successful. Please check your email to verify your account.')
                return redirect('login')
            except AuthRetryableError as e:
                if attempt < max_retries - 1:
                    time.sleep(2)  # Wait for 2 seconds before retrying
                    continue  # Retry the request
                else:
                    messages.error(request, "The sign-up operation timed out. Please try again later.")
                    return redirect('signup')
            except Exception as e:
                messages.error(request, f"An error occurred during signup: {str(e)}")
                return redirect('signup')
    return render(request, 'signup.html')

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            response = login_user(email, password)

            if response and response.user:
                user_id = response.user.id
                request.session['user_id'] = user_id
                messages.success(request, "Login successful!")
                return redirect('dashboard')
            else:
                if response.error:
                    error_message = response.error.message
                    if "Invalid login credentials" in error_message:
                        messages.error(request, "Incorrect password. Please try again.")
                    elif "User not found" in error_message:
                        messages.error(request, "No account found with this email. Please sign up.")
                    else:
                        messages.error(request, error_message)
                return redirect('login')

        except gotrue_errors.AuthApiError:
            messages.error(request, "Invalid login credentials. Please try again.")
            return redirect('login')

    return render(request, 'login.html')

def password_reset_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        response = reset_password(email)
        if response.error:
            messages.error(request, response.error.message)
            return redirect('password_reset')
        messages.success(request, 'Password reset email sent.')
        return redirect('login')
    return render(request, 'password_reset.html')

def logout_view(request):
    request.session.flush()
    messages.success(request, 'You have been logged out.')
    return redirect('main_page')

def dashboard_view(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    try:
        # Fetch user's products
        products_response = supabase.table('products').select('*').eq('user_id', user_id).execute()
        products = products_response.data if products_response.data else []

        # Fetch user's profile (handle empty result)
        profile_response = supabase.table('profiles').select('*').eq('user_id', user_id).limit(1).execute()
        profile = profile_response.data[0] if profile_response.data else {}

    except Exception as e:
        messages.error(request, f"Error fetching data: {str(e)}")
        products = []
        profile = {}

    return render(request, 'dashboard.html', {'products': products, 'profile': profile})

def product_detail_view(request, product_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    try:
        # Fetch the product from Supabase
        product_response = supabase.table('products').select('*').eq('id', product_id).single().execute()
        product = product_response.data

        if not product:
            messages.error(request, 'Product not found.')
            return redirect('dashboard')

        # Check if the product belongs to the logged-in user
        if product['user_id'] != user_id:
            messages.error(request, 'You are not authorized to view this product.')
            return redirect('dashboard')

        return render(request, 'product_detail.html', {'product': product})

    except Exception as e:
        messages.error(request, f"Error fetching product: {str(e)}")
        return redirect('dashboard')

def delete_product_view(request, product_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    if request.method == 'POST':
        try:
            # Fetch the product to ensure it belongs to the user
            product_response = supabase.table('products').select('user_id').eq('id', product_id).single().execute()
            product = product_response.data

            if not product or product['user_id'] != user_id:
                messages.error(request, 'You are not authorized to delete this product.')
                return redirect('dashboard')

            # Delete the product
            supabase.table('products').delete().eq('id', product_id).execute()
            messages.success(request, 'Product deleted successfully.')
        except Exception as e:
            messages.error(request, f"Error deleting product: {str(e)}")
    return redirect('dashboard')

def generate_product_view(request):
    """
    Handles the initial form submission from the dashboard.
    Stores the product_url and language in the session and redirects to step 2.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    if request.method == 'POST':
        # Get product URL and language from the dashboard form
        product_url = request.POST.get('product_url')
        language = request.POST.get('language')

        if not product_url or not language:
            messages.error(request, 'Product URL and language are required.')
            return redirect('dashboard')

        # Validate product_url
        validator = URLValidator()
        try:
            validator(product_url)
        except ValidationError:
            messages.error(request, 'Enter a valid Product URL.')
            return redirect('dashboard')

        # Store in session
        request.session['product_generation'] = {
            'product_url': product_url,
            'language': language,
        }

        # Render image selection step immediately
        return render(request, 'generate_product_step2.html', {
            'title': 'Fetching Images...',  # Placeholder, will be updated via AJAX
            'language': language,
        })

    # If GET request, redirect to dashboard
    return redirect('dashboard')


def fetch_images_view(request):
    """
    Handles AJAX requests to fetch images from the product URL.
    Returns a JSON response with images and product title.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    # Get product_url and language from session
    product_generation = request.session.get('product_generation')
    if not product_generation:
        return JsonResponse({'error': 'No product generation data found.'}, status=400)

    product_url = product_generation.get('product_url')
    language = product_generation.get('language')

    if not product_url or not language:
        return JsonResponse({'error': 'Product URL and language are required.'}, status=400)

    # Validate product_url
    validator = URLValidator()
    try:
        validator(product_url)
    except ValidationError:
        return JsonResponse({'error': 'Invalid product URL provided.'}, status=400)

    # Fetch and process images
    try:
        response = requests.get(product_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract product title
        title_tag = soup.find('h1')
        title = title_tag.text.strip() if title_tag else "Product Title"

        # Extract images and their dimensions
        images = []
        image_tags = soup.find_all('img')
        for img in image_tags:
            img_src = img.get('src')
            if img_src is None:
                continue
            if not img_src.startswith(('http://', 'https://')):
                img_src = 'https:' + img_src
            if img_src and img_src.startswith('http'):
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
                except Exception:
                    continue  # Skip images that cannot be processed

        if not images:
            return JsonResponse({'error': 'No valid images found on the product page.'}, status=400)

        # Sort images by dimensions (area) from largest to smallest
        images.sort(key=lambda x: x['width'] * x['height'], reverse=True)

        # Optionally, limit the number of images to prevent overload
        MAX_IMAGES = 100
        images = images[:MAX_IMAGES]

        # Update session with title and images
        request.session['product_generation']['title'] = title
        request.session['product_generation']['images'] = images

        # Return the images and title
        return JsonResponse({
            'title': title,
            'language': language,
            'images': images
        })

    except requests.exceptions.RequestException as e:
        return JsonResponse({'error': f"Error fetching product data: {str(e)}"}, status=500)
    
def review_product_view(request):
    """
    Handles the submission of selected images.
    Generates the AI structured summary and renders the review page (step 3).
    """
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    if request.method == 'POST':
        selected_images = request.POST.getlist('selected_images')
        title = request.POST.get('title')
        language = request.POST.get('language')

        if not selected_images:
            messages.error(request, 'Please select at least one image.')
            return redirect('generate_product')

        # Retrieve product URL from the session
        product_generation = request.session.get('product_generation')
        if not product_generation:
            messages.error(request, 'Product generation data not found.')
            return redirect('dashboard')

        product_url = product_generation.get('product_url')

        # Scrape text content from the product URL
        try:
            response = requests.get(product_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            # Extract all text content
            text_content = soup.get_text(separator='\n', strip=True)

        except requests.exceptions.RequestException as e:
            messages.error(request, f"Error fetching product data: {str(e)}")
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
            # Call OpenAI API for content analysis
            completion = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": analysis_prompt}]
            )
            response_text = completion.choices[0].message.content
        except Exception as e:
            messages.error(request, f"Error generating AI description: {str(e)}")
            return redirect('dashboard')

        # Parse the AI's response
        try:
            # Initialize dictionaries to hold parsed data
            parsed_data = {
                'title': '',
                'descriptions': [],
                'key_benefits': [],
                'reviews': [],
                'hooks': [],
                'full_names': [],
            }

            # Split the response by lines
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
                elif line.startswith('_Image Links:'):
                    # We'll replace these with selected images
                    current_section = 'image_links'
                elif line.startswith('_Full Names:'):
                    current_section = 'full_names'
                    names = line[len('_Full Names:'):].strip().rstrip('|').split(' | ')
                    parsed_data['full_names'] = names
                else:
                    # Handle multiline sections if necessary
                    if current_section in ['descriptions', 'key_benefits', 'reviews', 'hooks', 'full_names']:
                        parsed_data[current_section].append(line.rstrip('|').strip())

            # Replace Image Links with selected images
            parsed_data['images'] = selected_images[:5]  # Limit to 5 images

            # Store parsed data in session for later use
            request.session['product_generation']['parsed_data'] = parsed_data

            # Load the Shopify JSON template
            try:
            # Load Shopify JSON template with UTF-8 encoding
                template_path = os.path.join(settings.BASE_DIR, 'shopify_template.json')
                with open(template_path, 'r', encoding='utf-8') as file:
                    shopify_template = file.read()
            except UnicodeDecodeError as e:
                messages.error(request, f"Error reading Shopify template file: {str(e)}")
                return redirect('dashboard')

            # Replace placeholders in the template with parsed_data
            formatted_json = shopify_template
            replacements = {}

            for key, value in parsed_data.items():
                if isinstance(value, list):
                    for idx, item in enumerate(value):
                        placeholder = f"{{data['{key}'][{idx}]}}"
                        replacements[placeholder] = item
                else:
                    placeholder = f"{{data['{key}']}}"
                    replacements[placeholder] = value

            # Perform replacements
            for placeholder, actual_value in replacements.items():
                # Escape backslashes and double quotes in actual_value
                actual_value = actual_value.replace('\\', '\\\\').replace('"', '\\"')
                formatted_json = formatted_json.replace(placeholder, actual_value)

            # Add the formatted JSON to parsed_data
            parsed_data['json_template'] = formatted_json

            # Store parsed_data in session for later use
            request.session['product_generation']['parsed_data'] = parsed_data

            # Render the review page with parsed data and the JSON template
            return render(request, 'generate_product_step3.html', {
                'title': parsed_data.get('title'),
                'language': language,
                'images': parsed_data.get('images', []),
                'descriptions': parsed_data.get('descriptions', []),
                'key_benefits': parsed_data.get('key_benefits', []),
                'reviews': parsed_data.get('reviews', []),
                'hooks': parsed_data.get('hooks', []),
                'full_names': parsed_data.get('full_names', []),
                'json_template': parsed_data.get('json_template', '')
            })

            # Render the review page with parsed data
            return render(request, 'generate_product_step3.html', parsed_data)

        except Exception as e:
            messages.error(request, f"Error parsing AI response: {str(e)}")
            return redirect('dashboard')

    # If GET request, redirect to dashboard
    return redirect('dashboard')


def image_selection_view(request):
    """
    Handles the submission of selected images.
    Saves the product and redirects back to the dashboard.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    if request.method == 'POST':
        selected_images = request.POST.getlist('selected_images')
        title = request.POST.get('title')
        language = request.POST.get('language')

        if not selected_images:
            messages.error(request, 'Please select at least one image.')
            return redirect('dashboard')

        # Generate AI description (Assuming this function is defined elsewhere)
        description, tokens_used = generate_ai_description(title, language)

        # Save the product (Replace with your actual saving logic, e.g., Supabase)
        try:
            # Example: Insert into Supabase
            supabase.table('products').insert({
                'user_id': user_id,
                'title': title,
                'description': description,
                'language': language,
                'images': selected_images,
            }).execute()
            messages.success(request, 'Product page created successfully.')
            # Clear session data
            del request.session['product_generation']
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f"Failed to save product: {str(e)}")
            return redirect('dashboard')

    # If GET request, redirect to dashboard
    return redirect('dashboard')

def save_product_view(request):
    """
    Handles the final submission from the review page to save the product.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        language = request.POST.get('language')
        selected_images = request.POST.getlist('images[]')

        if not selected_images:
            messages.error(request, 'No images selected.')
            return redirect('dashboard')

        # Save the product (Replace with your actual saving logic, e.g., Supabase)
        try:
            # Example: Insert into Supabase
            supabase.table('products').insert({
                'user_id': user_id,
                'title': title,
                'description': description,
                'language': language,
                'images': selected_images,
            }).execute()
            messages.success(request, 'Product page created successfully.')
            # Clear session data
            del request.session['product_generation']
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f"Failed to save product: {str(e)}")
            return redirect('dashboard')

    # If GET request, redirect to dashboard
    return redirect('dashboard')


def shopify_auth_view(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')
    shop = request.GET.get('shop')
    if not shop:
        messages.error(request, 'Shop parameter is missing.')
        return redirect('dashboard')

    api_key = settings.SHOPIFY_API_KEY
    scopes = ['write_products']
    redirect_uri = request.build_absolute_uri(reverse('shopify_callback'))

    shopify.Session.setup(api_key=api_key, secret=settings.SHOPIFY_API_SECRET)
    session = shopify.Session(shop, api_version='2021-04')
    permission_url = session.create_permission_url(scopes, redirect_uri)

    return redirect(permission_url)

def shopify_callback_view(request):
    params = request.GET.dict()
    shop = params.get('shop')
    if not shop:
        messages.error(request, 'Shop parameter is missing.')
        return redirect('dashboard')

    api_key = settings.SHOPIFY_API_KEY
    api_secret = settings.SHOPIFY_API_SECRET

    shopify.Session.setup(api_key=api_key, secret=api_secret)
    try:
        session = shopify.Session(shop, api_version='2021-04')
        access_token = session.request_token(params)
    except Exception as e:
        messages.error(request, f"Error obtaining Shopify access token: {str(e)}")
        return redirect('dashboard')

    # Save access_token and shop URL to session
    request.session['shopify_access_token'] = access_token
    request.session['shop_url'] = shop

    messages.success(request, 'Shopify account connected successfully.')
    return redirect('dashboard')

def import_to_shopify_view(request, product_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    # Fetch product data from Supabase
    try:
        product_response = supabase.table('products').select('*').eq('id', product_id).single().execute()
        product = product_response.data

        if not product:
            messages.error(request, 'Product not found.')
            return redirect('dashboard')

        # Fetch user's Shopify credentials from profiles table
        profile_response = supabase.table('profiles').select('*').eq('user_id', user_id).single().execute()
        profile = profile_response.data

        if not profile or not profile.get('shop_url') or not profile.get('shopify_api_key') or not profile.get('shopify_api_secret'):
            messages.error(request, 'Please configure your Shopify credentials in the settings page.')
            return redirect('settings')

        shop_url = profile['shop_url']
        shopify_api_key = profile['shopify_api_key']
        shopify_api_secret = profile['shopify_api_secret']
        api_version = '2023-01'  # Use the desired API version

        # Initialize Shopify session
        initialize_shopify_session(shop_url, api_version, shopify_api_secret)

        # Create a new product in Shopify
        new_product = shopify.Product()
        new_product.title = product['title']
        new_product.body_html = product['description']
        # Add images
        if product.get('images'):
            new_product.images = [{'src': img} for img in product['images']]
        success = new_product.save()
        shopify.ShopifyResource.clear_session()

        if success:
            messages.success(request, 'Product imported to Shopify successfully.')
        else:
            messages.error(request, 'Failed to import product to Shopify.')

    except Exception as e:
        messages.error(request, f"Error importing to Shopify: {str(e)}")
        shopify.ShopifyResource.clear_session()

    return redirect('dashboard')


def settings_view(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        shop_url = request.POST.get('shop_url')
        shopify_api_secret = request.POST.get('shopify_api_secret')

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
            response = supabase.table('profiles').upsert(profile_data).execute()
            messages.success(request, 'Profile updated successfully.')
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f"Error updating profile: {str(e)}")
            return redirect('settings')

    else:
        # Fetch existing profile data (allowing for cases with 0 rows)
        try:
            profile_response = supabase.table('profiles').select('*').eq('user_id', user_id).limit(1).execute()
            profile = profile_response.data[0] if profile_response.data else {}
        except Exception as e:
            messages.error(request, f"Error fetching profile: {str(e)}")
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

def handler404(request, exception):
    return render(request, '404.html', status=404)

def handler500(request):
    return render(request, '500.html', status=500)
