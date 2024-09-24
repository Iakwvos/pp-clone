from django.urls import path
from . import views

urlpatterns = [

    # Main and Authentication
    path('', views.main_page, name='main_page'),
    path('signup/', views.signup_view, name='signup'),

    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    path('password_reset/', views.password_reset_view, name='password_reset'),

    # Dashboard and Settings

    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('settings/', views.settings_view, name='settings'),


    # Product Management
    path('product/<int:product_id>/', views.product_detail_view, name='product_detail'),

    path('product/delete/<int:product_id>/', views.delete_product_view, name='delete_product'),

    path('product/generate/', views.generate_product_view, name='generate_product'),
    path('product/save/', views.save_product_view, name='save_product'),
    path('generate_product/', views.generate_product_view, name='generate_product'),  # Duplicate, consider removing

    path('upgrade_plan/', views.upgrade_plan_view, name='upgrade_plan'),

    path('stores/edit/<uuid:store_id>/', views.edit_store_view, name='edit_store'),
    path('stores/delete/<uuid:store_id>/', views.delete_store_view, name='delete_store'),
    path('stores/connect/', views.connect_store_view, name='connect_store'),
    path('import-shopify/', views.import_to_shopify_view, name='import_to_shopify'),
    # Image and Review

    path('fetch_images/', views.fetch_images_view, name='fetch_images'),

    path('review_product/', views.review_product_view, name='review_product'),

    path('import-to-shopify/', views.import_to_shopify_view, name='import_to_shopify'),

    path('privacy_policy/', views.handler404),
    path('terms_of_use/', views.handler404),
    path('contact/', views.handler404),
    path('blog/', views.handler404),
    # Error Handling

    path('404/', views.handler404),

    path('500/', views.handler500),




]
