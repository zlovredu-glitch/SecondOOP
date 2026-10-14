import hashlib
import uuid
import hmac
import os

class Product:
    def __init__(self, name, price):
        self.name = name
        self.price = price

    def __str__(self):
        return f"{self.name}, цена: {self.price} руб."

    def __repr__(self):
        return f"Product('{self.name}', {self.price})"

    def __eq__(self, other):
        if isinstance(other, Product):
            return self.price == other.price
        return False

    def __lt__(self, other):
        if isinstance(other, Product):
            return self.price < other.price
        return NotImplemented

class Discount:
    def __init__(self, description, discount_percent):
        self.description = description
        self.discount_percent = discount_percent

    @staticmethod
    def calculate_discounted_price(price, discount_percent):
        return price * (1 - discount_percent / 100)

    @staticmethod
    def seasonal_discount(price):
        return Discount.calculate_discounted_price(price, 10)  # 10% скидка

    @staticmethod
    def promo_code_discount(price):
        return Discount.calculate_discounted_price(price, 15)  # 15% скидка

class Order:
    total_orders = 0
    total_sum = 0

    def __init__(self, products):
        self.products = products
        Order.total_orders += 1
        Order.total_sum += self.get_total()

    def get_total(self):
        total = sum(product.price for product in self.products)
        return total

    def apply_discount(self, discount_method):
        total = self.get_total()
        discounted_total = discount_method(total)
        return discounted_total

    @classmethod
    def get_total_orders(cls):
        return cls.total_orders

    @classmethod
    def get_total_sum(cls):
        return cls.total_sum

    def __str__(self):
        products_str = ', '.join(str(product) for product in self.products)
        return f"Заказ: [{products_str}], {self.get_total()} руб."

    def __repr__(self):
        return f"Order({self.products})"

class User:
    """
    Базовый класс, представляющий пользователя.
    """
    users = []  # Список для хранения всех пользователей

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password_hash = self.hash_password(password)

    @staticmethod
    def hash_password(password):
        """Создаёт хеш пароля с уникальной солью."""
        salt = os.urandom(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            600_000
        )
        return salt.hex() + "$" + password_hash.hex()

    @staticmethod
    def check_password(stored_password, provided_password):
        """
        Проверка пароля.
        """
        try:
            salt_hex, hash_hex = stored_password.split("$", 1)
            salt = bytes.fromhex(salt_hex)
            expected_hash = bytes.fromhex(hash_hex)

            actual_hash = hashlib.pbkdf2_hmac(
                "sha256",
                provided_password.encode("utf-8"),
                salt,
                600_000
            )

            return hmac.compare_digest(expected_hash, actual_hash)
        except (ValueError, TypeError):
            return False

    def get_details(self):
        return {
            "username": self.username,
            "email": self.email,
            "role": self.__class__.__name__
        }


class Customer(User):
    """
    Класс, представляющий клиента, наследующий класс User.
    """
    def __init__(self, username, email, password, address):
        super().__init__(username, email, password)
        self.address = address
        self.orders = []

    def add_order(self, order):
        self.orders.append(order)

    def __str__(self):
        return f"Клиент: {self.username}, Заказы: {len(self.orders)}"

    def __repr__(self):
        return f"Customer('{self.name}')"

    def get_details(self):
        details = super().get_details()
        details["address"] = self.address
        return details

class Admin(User):
    """
    Класс, представляющий администратора, наследующий класс User.
    """
    def __init__(self, username, email, password, admin_level):
        super().__init__(username, email, password)
        self.admin_level = admin_level

    def get_details(self):
        details = super().get_details()
        details["admin_level"] = self.admin_level
        return details

    @staticmethod
    def list_users(current_user):
        """Показывает пользователей только администратору."""
        if not isinstance(current_user, Admin):
            print("Ошибка: доступ разрешён только администратору.")
            return

        for user in User.users:
            print(user.get_details())

    @staticmethod
    def delete_user(username, current_user):
        """Удаляет пользователя только по запросу администратора."""
        if not isinstance(current_user, Admin):
            print("Ошибка: доступ разрешён только администратору.")
            return False

        for user in User.users:
            if user.username == username:
                if user is current_user:
                    print("Нельзя удалить текущего администратора.")
                    return False

                User.users.remove(user)
                print(f"Пользователь {username} удалён.")
                return True

        print(f"Пользователь {username} не найден.")
        return False

class AuthenticationService:
    """
    Сервис для управления регистрацией и аутентификацией пользователей.
    """
    def __init__(self):
        self.sessions = {}
        self.current_token = None

    def register(self, user_class, username, email, password, *args):
        """
        Регистрация нового пользователя.
        """
        if user_class not in (Customer, Admin):
            return "Ошибка: неизвестный тип пользователя."

        if not username or not email or not password:
            return "Ошибка: заполните все обязательные поля."

        if any(user.username == username for user in User.users):
            return "Ошибка: имя пользователя уже занято."

        user = user_class(username, email, password, *args)
        User.users.append(user)

        return f"Пользователь {username} успешно зарегистрирован."

    def login(self, username, password):
        """
        Аутентификация пользователя.
        """
        user = next((u for u in User.users if u.username == username),None)
        if user is None or not User.check_password(user.password_hash, password):
            return "Ошибка: неверное имя пользователя или пароль."

        token = uuid.uuid4().hex
        self.sessions[token] = user
        self.current_token = token

        return f"Вход выполнен: {username}."


    def logout(self):
        """
        Выход пользователя из системы.
        """
        if self.current_token is None:
            return "Ошибка: пользователь не вошёл в систему."

        self.sessions.pop(self.current_token, None)
        self.current_token = None

        return "Выход выполнен успешно."

    def get_current_user(self):
        """
        Возвращает текущего вошедшего пользователя.
        """
        if self.current_token is None:
            return None

        return self.sessions.get(self.current_token)


# Пример использования

auth_service = AuthenticationService()

print(auth_service.register(
    Customer, "Yogan", "yogan@example.com",
    "secret123", "Москва"
))

print(auth_service.register(
    Admin, "admin", "admin@example.com",
    "admin123", 1
))

# Вход клиента
print(auth_service.login("Yogan", "secret123"))
print(auth_service.get_current_user().get_details())
curr_user = auth_service.get_current_user()
#
Admin.list_users(curr_user)
print(auth_service.logout())

# Вход администратора
print(auth_service.login("admin", "admin123"))

curr_user = auth_service.get_current_user()

# Создание продуктов
product1 = Product('Ноутбук', 50000)
product2 = Product('Мышь', 1000)
product3 = Product('Клавиатура', 3000)

# Создание клиентов
print(auth_service.register(
    Customer, "Иван", "ivanRus@example.com",
    "NotASecret123", "Саратов"
))

print(auth_service.register(
    Customer, "Мария", "Mary@example.com",
    "MainSecret123", "Воронеж"
))

customer1 = next(u for u in User.users if u.username == "Иван")
customer2 = next(u for u in User.users if u.username == "Мария")

# Создание заказов
order1 = Order([product1, product2])
customer1.add_order(order1)

order2 = Order([product3])
customer2.add_order(order2)

order3 = Order([product2, product3])
customer1.add_order(order3)

# Применение скидок
print(f"Стоимость заказа 1 без скидки: {order1.get_total()}")
print(f"Стоимость заказа 1 с сезонной скидкой: {order1.apply_discount(Discount.seasonal_discount)}")
print(f"Стоимость заказа 1 со скидкой по промокоду: {order1.apply_discount(Discount.promo_code_discount)}")

# Подсчёт общего количества заказов и общей суммы
print(f"Общее количество заказов: {Order.get_total_orders()}")
print(f"Общая сумма всех заказов: {Order.get_total_sum()}")

# Просмотр списка пользователей
Admin.list_users(curr_user)

# Удаление клиента
Admin.delete_user("ivan", curr_user)
Admin.delete_user("Yogan", curr_user)

# Вывод информации о клиентах и заказах
for customer in [customer1, customer2]:
    print(customer)
    for order in customer.orders:
        print(f"  {order}")

# Выход администратора
print(auth_service.logout())
