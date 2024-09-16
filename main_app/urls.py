from django.urls import path
from . import views

urlpatterns = [
    path('', views.main_page, name='main_page'),
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('password_reset/', views.password_reset_view, name='password_reset'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('product/<int:product_id>/', views.product_detail_view, name='product_detail'),
    path('product/delete/<int:product_id>/', views.delete_product_view, name='delete_product'),
    path('product/generate/', views.generate_product_view, name='generate_product'),
    path('product/save/', views.save_product_view, name='save_product'),
    path('shopify/auth/', views.shopify_auth_view, name='shopify_auth'),
    path('shopify/callback/', views.shopify_callback_view, name='shopify_callback'),
    path('product/import/<int:product_id>/', views.import_to_shopify_view, name='import_to_shopify'),
    path('settings/', views.settings_view, name='settings'), # Assuming you have a dashboard view
    path('generate_product/', views.generate_product_view, name='generate_product'),
    path('fetch_images/', views.fetch_images_view, name='fetch_images'),
    path('save_product/', views.image_selection_view, name='save_product'),
    path('review_product/', views.review_product_view, name='review_product'),

    # Error handling
    
    path('404/', views.handler404),
    path('500/', views.handler500),
]
