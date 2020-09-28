from setuptools import setup

setup(name='friezeauth',
      version='0.0.1',
      description='Super simple certificate authority manager',
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3.6',
      ],
      keywords='certificate authority',
      url='http://github.com/kchoudhu/friezeauth',
      author='Kamil Choudhury',
      author_email='kamil.choudhury@anserinae.net',
      license='BSD',
      packages=['friezeauth'],
      install_requires=[
          'toml',
          'cryptography'
      ],
      include_package_data=True,
      zip_safe=False)
