from django.contrib import admin
from django.urls import path, include
from main_app import views as main_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', main_views.main_page, name='main_page'),
    path('auth/', include('main_app.urls')),
    path('dashboard/', main_views.dashboard_view, name='dashboard'),
    path('generate_product/', main_views.generate_product_view, name='generate_product'),
    path('save_product/', main_views.save_product_view, name='save_product'),
    path('shopify_auth/', main_views.shopify_auth_view, name='shopify_auth'),
    path('shopify_callback/', main_views.shopify_callback_view, name='shopify_callback'),
    path('import_to_shopify/<int:product_id>/', main_views.import_to_shopify_view, name='import_to_shopify'),
    path('logout/', main_views.logout_view, name='logout'),
    # Add any other routes as needed
]

handler404 = 'main_app.views.handler404'
handler500 = 'main_app.views.handler500'
