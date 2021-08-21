[![](https://jitpack.io/v/joyner-perez/aes_dukpt_x9.24-3-2017.svg)](https://jitpack.io/#joyner-perez/aes_dukpt_x9.24-3-2017)
# Java AES DUKPT Library

Implementation of the ANSI AES DUKPT standard: specified within Retail Financial Services Symmetric Key Management Part 3: Using Symmetric Techniques (ANSI X9.24-3:2017).

How to install with Gradle
--------------
1. Add it in your root build.gradle at the end of repositories:

		allprojects {
			repositories {
				...
				maven { url 'https://jitpack.io' }
			}
		}

2. Add the dependency:

		dependencies {
			implementation 'com.github.joyner-perez:aes_dukpt_x9.24-3-2017:1.0.1'
		}





How to install with Maven
--------------
1. Add the JitPack repository to your build file:

        <repositories>
            <repository>
                    <id>jitpack.io</id>
                    <url>https://jitpack.io</url>
            </repository>
        </repositories>

   1. Add the dependency:

           <dependency>
               <groupId>com.github.joyner-perez</groupId>
               <artifactId>aes_dukpt_x9.24-3-2017</artifactId>
               <version>1.0.1</version>
           </dependency>


