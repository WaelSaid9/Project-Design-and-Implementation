"""
Demo file for testing the password management system
Comprehensive tests and demonstrations for the emoji password manager
"""

from password_manager import EmojiPasswordManager
import unittest


def demo_password_system():
    """
    Demonstration of the password management system
    Shows all features and capabilities
    """
    print("🚀 Starting Password Management System Demo")
    print("=" * 60)

    # Create password manager
    manager = EmojiPasswordManager("demo_passwords.db")

    # Test passwords with emojis
    test_passwords = [
        ("Wael", "Wael@9!3?🫡🤍", "master123"),
        ("Ahmed", "SecurePass$2024🔐✅", "master123"),
        ("Sara", "MyPassword123!😊💯", "master123"),
        ("Omar", "Admin@Pass#123🚀🎯", "master123")
    ]

    print("\n1️⃣ Testing password saving:")
    print("-" * 40)

    for username, password, master_pass in test_passwords:
        print(f"\n👤 Saving password for user: {username}")
        print(f"🔑 Password: {password}")

        # Analyze password before saving
        analysis = manager.validate_password_input(password)
        print(f"📊 Analysis:")
        print(f"   - Length: {analysis['length']} characters")
        print(f"   - Has letters: {analysis['has_letters']}")
        print(f"   - Has numbers: {analysis['has_numbers']}")
        print(f"   - Has symbols: {analysis['has_symbols']}")
        print(f"   - Has emojis: {analysis['has_emojis']}")
        print(f"   - Emoji count: {analysis['emoji_count']}")
        print(f"   - Emoji list: {analysis['emoji_list']}")

        # Save password
        success = manager.save_password(username, password, master_pass)
        if success:
            print("✅ Saved successfully!")
        else:
            print("❌ Failed to save!")

        print("-" * 40)

    print("\n2️⃣ Testing password retrieval:")
    print("-" * 40)

    for username, original_password, master_pass in test_passwords:
        retrieved_password = manager.get_password(username, master_pass)
        if retrieved_password:
            print(f"👤 {username}:")
            print(f"   🔐 Original: {original_password}")
            print(f"   🔓 Retrieved: {retrieved_password}")
            print(f"   ✅ Match: {original_password == retrieved_password}")
        else:
            print(f"❌ Failed to retrieve password for {username}")
        print("-" * 40)

    print("\n3️⃣ Displaying all users:")
    print("-" * 40)

    users = manager.list_users()
    for i, user in enumerate(users, 1):
        print(f"{i}. 👤 {user['username']}")
        print(f"   💪 Strength: {user['strength']}")
        print(f"   😊 Emoji count: {user['emoji_count']}")
        print(f"   📅 Date: {user['created_at']}")
        print("-" * 30)

    print("\n4️⃣ Testing password strength analysis:")
    print("-" * 40)

    test_strength_passwords = [
        "123456",
        "password",
        "Password123",
        "P@ssw0rd123",
        "Wael@9!3?🫡🤍"
    ]

    for pwd in test_strength_passwords:
        strength = manager.check_password_strength(pwd)
        print(f"🔑 Password: {pwd}")
        print(
            f"💪 Strength: {strength['strength_text']} ({strength['score']}/4)")
        print(f"⏱️ Crack time: {strength['crack_time']}")
        print("-" * 30)

    print("\n🎉 Demo completed successfully!")


class TestEmojiPasswordManager(unittest.TestCase):
    """
    Unit tests for the password management system
    Comprehensive testing of all features
    """

    def setUp(self):
        """Setup test data"""
        self.manager = EmojiPasswordManager("test_passwords.db")
        self.test_password = "TestPass123!🔐"
        self.master_password = "master123"
        self.username = "testuser"

    def test_password_validation(self):
        """Test password validation"""
        analysis = self.manager.validate_password_input(self.test_password)

        self.assertTrue(analysis['is_valid'])
        self.assertTrue(analysis['has_letters'])
        self.assertTrue(analysis['has_numbers'])
        self.assertTrue(analysis['has_symbols'])
        self.assertTrue(analysis['has_emojis'])
        self.assertEqual(analysis['emoji_count'], 1)

    def test_emoji_detection(self):
        """Test emoji detection"""
        emoji_password = "Hello😊World🌍Test💯"
        analysis = self.manager.validate_password_input(emoji_password)

        self.assertTrue(analysis['has_emojis'])
        self.assertEqual(analysis['emoji_count'], 3)
        self.assertIn('😊', analysis['emoji_list'])
        self.assertIn('🌍', analysis['emoji_list'])
        self.assertIn('💯', analysis['emoji_list'])

    def test_encryption_decryption(self):
        """Test encryption and decryption"""
        encrypted, salt = self.manager.encrypt_password(
            self.test_password, self.master_password)
        decrypted = self.manager.decrypt_password(
            encrypted, self.master_password, salt)

        self.assertEqual(self.test_password, decrypted)

    def test_password_strength(self):
        """Test password strength checking"""
        weak_password = "123456"
        strong_password = "Wael@9!3?🫡🤍"

        weak_analysis = self.manager.check_password_strength(weak_password)
        strong_analysis = self.manager.check_password_strength(strong_password)

        self.assertLess(weak_analysis['score'], strong_analysis['score'])

    def test_save_and_retrieve_password(self):
        """Test saving and retrieving passwords"""
        # Save password
        success = self.manager.save_password(
            self.username, self.test_password, self.master_password)
        self.assertTrue(success)

        # Retrieve password
        retrieved = self.manager.get_password(
            self.username, self.master_password)
        self.assertEqual(self.test_password, retrieved)


if __name__ == "__main__":
    print("🧪 Running tests...")

    # Run unit tests
    unittest.main(verbosity=2, exit=False)

    # Run demonstration
    print("\n" + "="*60)
    demo_password_system()
