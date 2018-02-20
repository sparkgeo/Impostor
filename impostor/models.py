
from django.db import models
import hashlib, time
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.conf import settings

# Create your models here.


class ImpostorLog(models.Model):

    user = getattr(settings, 'AUTH_USER_MODEL', User)

    impostor = models.ForeignKey(user, on_delete=models.CASCADE, related_name='impostor', db_index=True)
    imposted_as = models.ForeignKey(user, on_delete=models.CASCADE, related_name='imposted_as',
                                    verbose_name='Logged in as', db_index=True)
    impostor_ip = models.GenericIPAddressField(verbose_name="Impostor's IP address", null=True, blank=True)
    logged_in = models.DateTimeField(auto_now_add=True, verbose_name='Logged on')
    # These last two will come into play with Django 1.3+, but are here now for easier migration
    logged_out = models.DateTimeField(null=True, blank=True)
    token = models.CharField(max_length=32, blank=True, db_index=True)

    def save(self, *args, **kwargs):
        if not self.token and self.impostor:
            self.token = hashlib.sha1(self.impostor.username+str(time.time())).hexdigest()[:32]
        super(ImpostorLog, self).save(*args, **kwargs)
