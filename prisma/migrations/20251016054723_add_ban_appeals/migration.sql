-- CreateTable
CREATE TABLE "BanAppeal" (
    "id" SERIAL NOT NULL,
    "content" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,

    CONSTRAINT "BanAppeal_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "BanAppeal_userId_key" ON "BanAppeal"("userId");

-- AddForeignKey
ALTER TABLE "BanAppeal" ADD CONSTRAINT "BanAppeal_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
