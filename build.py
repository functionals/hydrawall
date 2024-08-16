# -*- coding: utf-8 -*-
"""
Created on Thu Aug 15 18:29:32 2024

@author: M
"""
# build.py


class BuildConfig:
    def __init__(self, config_name='default'):
        self.config_name = config_name
        print(f"BuildConfig instance created with config: {self.config_name}")

    def prepare(self):
        print("Preparing build configuration...")
        # Add any setup steps needed before the build here

    def build(self):
        print("Building with configuration:", self.config_name)
        # Call build library functions or use custom build logic here

    def run(self):
        print("Running build with configuration:", self.config_name)
        self.prepare()
        self.build()

def main():
    # Instantiate the BuildConfig class and call methods
    build_config = BuildConfig(config_name='release')
    build_config.run()

if __name__ == "__main__":
    main()
