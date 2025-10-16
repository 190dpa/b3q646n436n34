-- CreateTable
CREATE TABLE "GiftLink" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "giftType" TEXT NOT NULL,
    "giftValue" TEXT NOT NULL,
    "giftMeta" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "claimed" BOOLEAN NOT NULL DEFAULT false,
    "claimedByUserId" TEXT,

    CONSTRAINT "GiftLink_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "GiftLink_token_key" ON "GiftLink"("token");
