package com.abhipoc.awsazure.iam;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.rest.Response;
import com.azure.identity.ManagedIdentityCredential;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.IamException;
import software.amazon.awssdk.services.iam.model.ListAccessKeysRequest;
import software.amazon.awssdk.services.iam.model.ListAccessKeysResponse;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;

import java.util.Optional;



/**
 * Azure Functions with HTTP Trigger.
 */
public class Function {
    /**
     * This function listens at endpoint "/api/HttpExample". Two ways to invoke it using "curl" command in bash:
     * 1. curl -d "HTTP Body" {your host}/api/HttpExample
     * 2. curl "{your host}/api/HttpExample?name=HTTP%20Query"
     */
    @FunctionName("ProcessAccessKeyOperations")
    public HttpResponseMessage run(
            @HttpTrigger(
                name = "req",
                methods = {HttpMethod.GET, HttpMethod.POST},
                authLevel = AuthorizationLevel.ANONYMOUS)
                HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");

            try {
                String userName = "adf-security-hub-user";
                context.getLogger().info("Getting the list of Access Keys for the current IAM User");
                ListAccessKeysResponse response = listAccessKeys(context,userName);
                Gson gson = new Gson();
                if(response.hasAccessKeyMetadata()) {
                    if(response.accessKeyMetadata().size() > 0 ) {
                        context.getLogger().info("Storing the secret in the azure keyvault");
                        if(storeSecretinAzureKeyVault(context)) {
                            return request.createResponseBuilder(HttpStatus.OK).body("Successfully stored the secret in azure key vault").build();
                        }   
                    }
                } else {
                    return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR).body("Secret was not stored in Azure key vault").build();
                }
            }catch(Exception e) {
                context.getLogger().info("Exception occurred with a message "+e.getLocalizedMessage());
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Error Occurred").build();
            }
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Error Occurred").build();
    }

    private ListAccessKeysResponse listAccessKeys(ExecutionContext context, String userName) {
            try {
                    String accessKeyId = "<ClientID>";
                    String secretAccessKey = "<ClientSecret>";
                    Region region = Region.AWS_GLOBAL;
                    ListAccessKeysRequest request = ListAccessKeysRequest.builder().userName(userName).build();
                    IamClient iamClient = IamClient.builder().region(region).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKeyId, secretAccessKey))).build();
                    ListAccessKeysResponse response = iamClient.listAccessKeys(request);
                   return response;

             } catch(IamException e){
                context.getLogger().info("Exception occurred with a message "+e.awsErrorDetails().errorMessage());
                return null;
             } catch(Exception e) {
                context.getLogger().info("Exception occurred with a message "+e.getLocalizedMessage());
                return null;
             }
             
    }

    private boolean storeSecretinAzureKeyVault(ExecutionContext context){
        try {
            //ManagedIdentityCredential managedIdentityCredential = new ManagedIdentityCredentialBuilder().clientId("caee61ff-b395-43a7-82aa-6de7785827d0").build();
            TokenCredential managedIdentityCredential = new ManagedIdentityCredentialBuilder().build();
            SecretClient secretClient = new SecretClientBuilder().vaultUrl("https://awsazureautomations.vault.azure.net").credential(managedIdentityCredential).buildClient();
            KeyVaultSecret keyvaultSecret = new KeyVaultSecret("AccessKeyID", "<ClientID>");
            secretClient.setSecret("AWSAccessKeyID", "<ClientID>");
            Response<KeyVaultSecret> response =  secretClient.setSecretWithResponse(keyvaultSecret, null);
            ObjectMapper mapper = new ObjectMapper();
            String responseObj = mapper.writeValueAsString(response);
            context.getLogger().info("Response obtained from Key Vault Operation is "+responseObj);
            return true;

        }catch(Exception e) {
            context.getLogger().info("Exception occurred with a message "+e.getMessage());
            return false;
        }
        
    }


}
