
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from users.models import User
from .models import Wallet, WalletBalance
from currency.models import Currency

class WalletAPITests(APITestCase):
	def setUp(self):
		self.user = User.objects.create_user(phone_number="0771234567", email="user@example.com", password="testpass123")
		self.admin = User.objects.create_user(phone_number="0779999999", email="admin@example.com", password="adminpass123", is_staff=True)
		self.currency = Currency.objects.create(code="USD")
		self.wallet = Wallet.objects.create(user=self.user)
		WalletBalance.objects.create(wallet=self.wallet, currency=self.currency, balance=100)
		self.client = APIClient()

	def test_get_wallet_by_user_id_authenticated(self):
		self.client.force_authenticate(user=self.user)
		url = reverse('get_wallet_by_user_id') + f'?user_id={self.user.id}'
		response = self.client.get(url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertIn('balances', response.data)

	def test_get_wallet_by_user_id_permission_denied(self):
		self.client.force_authenticate(user=self.user)
		url = reverse('get_wallet_by_user_id') + f'?user_id={self.admin.id}'
		response = self.client.get(url)
		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

	def test_top_up_balance(self):
		self.client.force_authenticate(user=self.user)
		url = reverse('top_up_balance', args=[self.user.id, self.currency.code])
		data = {"amount": "50"}
		response = self.client.post(url, data)
		self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_201_CREATED])

	def test_deduct_balance(self):
		self.client.force_authenticate(user=self.user)
		url = reverse('deduct_balance', args=[self.user.id, self.currency.code])
		data = {"amount": "10"}
		response = self.client.post(url, data)
		self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_201_CREATED])
