package initializers

import models "jwt-auth/models"

func SyncDataBase() {
	DB.AutoMigrate(&models.User{})
}
