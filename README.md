## 使用构建工具集成

### maven
```xml
<dependencies>
    <dependency>
        <groupId>com.github.tencentyun</groupId>
        <artifactId>tls-sig-api</artifactId>
        <version>1.2</version>
    </dependency>
</dependencies>
```

### gradle
```java
dependencies {
    compile 'com.github.tencentyun:tls-sig-api:1.2'
}
```

### 源码构建
``` shell
./gradlew -b user_build.gradle build
```
生成的 jar 在 `build/libs` 下面可以找到。依赖需要自行到 [release](https://github.com/tencentyun/tls-sig-api-java/releases) 下载。


## 生成 sig

### 默认有效期接口
```java
import com.tls.tls_sigature.*;

GenTLSSignatureResult result = tls_sigature.genSig(140000000, "xiaojun", priKeyContent);
System.out.println(result.urlSig);
```

### 指定有效期接口
```java
import com.tls.tls_sigature.*;

GenTLSSignatureResult result = tls_sigature.GenTLSSignatureEx(140000000, "xiaojun", priKeyContent, 24*3600*180);
System.out.println(result.urlSig);
```
