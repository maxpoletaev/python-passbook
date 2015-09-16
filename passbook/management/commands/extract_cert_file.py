from django.core.management.base import BaseCommand
from passbook import utils
import os


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('pkcs12', type=str, help='.p12 file')
        parser.add_argument('dest', type=str, help='Destenation')

    def handle(self, *args, **options):
        utils.extract_cert_file(
            os.path.join(os.getcwd(), args[0]),
            os.path.join(os.getcwd(), args[1]),
        )
