from setuptools import setup, find_packages

version = '0.0.1'

setup(
    name="alerta2xmpp",
    version=version,
    description='Alerta plugin for XMPP',
    url='https://github.com/ccdcoe/CDMCS/tree/master/TICK/Alerta/alerta2xmpp',
    license='MIT',
    author='Hillar Aarelaid',
    author_email='hillar@aarelaid.net',
    packages=find_packages(),
    py_modules=['alerta2xmpp'],
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'alerta.plugins': [
            'xmpp = alerta2xmpp:XMPP'
        ]
    }
)
