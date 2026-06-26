import json

from django.test import Client, TestCase


class InvestigatorApiTests(TestCase):
	def setUp(self):
		self.client = Client()

	def test_health_endpoint(self):
		resp = self.client.get("/health")
		self.assertEqual(resp.status_code, 200)
		self.assertEqual(resp.json(), {"status": "ok"})

	def test_analyze_ticket_minimal_payload(self):
		payload = {
			"ticket_id": "TKT-MIN-1",
			"complaint": "My payment failed and money was deducted.",
			"transaction_history": [
				{
					"transaction_id": "TXN-1",
					"timestamp": "2026-04-14T14:08:22Z",
					"type": "payment",
					"amount": 1200,
					"counterparty": "MRC-12",
					"status": "failed",
				}
			],
		}

		resp = self.client.post(
			"/analyze-ticket",
			data=json.dumps(payload),
			content_type="application/json",
		)
		self.assertEqual(resp.status_code, 200)
		body = resp.json()

		required_fields = {
			"ticket_id",
			"relevant_transaction_id",
			"evidence_verdict",
			"case_type",
			"severity",
			"department",
			"agent_summary",
			"recommended_next_action",
			"customer_reply",
			"human_review_required",
		}
		self.assertTrue(required_fields.issubset(body.keys()))
		self.assertEqual(body["ticket_id"], "TKT-MIN-1")

		self.assertIn(body["evidence_verdict"], {"consistent", "inconsistent", "insufficient_data"})
		self.assertIn(
			body["case_type"],
			{
				"wrong_transfer",
				"payment_failed",
				"refund_request",
				"duplicate_payment",
				"merchant_settlement_delay",
				"agent_cash_in_issue",
				"phishing_or_social_engineering",
				"other",
			},
		)
		self.assertIn(body["severity"], {"low", "medium", "high", "critical"})
		self.assertIn(
			body["department"],
			{
				"customer_support",
				"dispute_resolution",
				"payments_ops",
				"merchant_operations",
				"agent_operations",
				"fraud_risk",
			},
		)

		self.assertIsInstance(body["human_review_required"], bool)
		self.assertIsInstance(body.get("confidence"), (int, float))
		self.assertGreaterEqual(body["confidence"], 0)
		self.assertLessEqual(body["confidence"], 1)
		self.assertIsInstance(body.get("reason_codes"), list)

	def test_malformed_json_returns_400(self):
		resp = self.client.post(
			"/analyze-ticket",
			data="{not-valid-json",
			content_type="application/json",
		)
		self.assertEqual(resp.status_code, 400)

	def test_empty_complaint_returns_422(self):
		payload = {"ticket_id": "TKT-EMPTY-1", "complaint": "   "}
		resp = self.client.post(
			"/analyze-ticket",
			data=json.dumps(payload),
			content_type="application/json",
		)
		self.assertEqual(resp.status_code, 422)

	def test_customer_reply_never_requests_credentials(self):
		payload = {
			"ticket_id": "TKT-SAFE-1",
			"complaint": "A caller asked for my OTP and PIN to fix my blocked account.",
			"transaction_history": [],
		}
		resp = self.client.post(
			"/analyze-ticket",
			data=json.dumps(payload),
			content_type="application/json",
		)
		self.assertEqual(resp.status_code, 200)
		reply = resp.json()["customer_reply"].lower()

		forbidden_requests = [
			"share your otp",
			"send your otp",
			"provide your pin",
			"share your password",
		]
		self.assertFalse(any(s in reply for s in forbidden_requests))
